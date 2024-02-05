#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

# Set shell options to exit on error and treat unset variables as errors
set -e
set -u

# Default output directory
OUTDIR=/tmp/aeld

# Git repository and version information for the Linux kernel and Version of BusyBox to be used
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1

# Directory of the finder application and Target architecture mentioned as ARM with cross compile prefix given.
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-

#step1 given  to Check if a custom output directory is provided as a command-line argument
if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

# Create the output directory if it is not already there
mkdir -p ${OUTDIR}


# Change to the output directory
cd "$OUTDIR"

# Check if the Linux kernel repository is not already cloned
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi

# Check if the kernel image for the specified architecture does not exist
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}
# TODO: Add your kernel build steps here
# Clean the kernel source tree
# Removing the .config files of any existing configuarations
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper
# Configure the kernel for our virt board we create using the QEMU
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
# Build the kernel for multiple cpus and build a kernel image to booting on QEMU.
make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all
# Build device tree binaries
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs
fi

# Copy the built kernel image to the specified output directory
echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}
echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"

# Check if the root filesystem directory already exists
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
	# Remove the existing root filesystem directory
    	sudo rm  -rf ${OUTDIR}/rootfs
fi

# TODO: Create necessary base directories
# Filesystem  hierarchy and its content and application of it.
# bin - programs for all users, used at boot
# dev - device nodes and other files
# etc - system configuration files
mkdir -p "${OUTDIR}"/rootfs
cd "${OUTDIR}"/rootfs
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
# additional programs libraries, utilities
mkdir -p usr/bin usr/lib usr/sbin
# files modified at runtime and needed after the boot.
mkdir -p var/log home/conf

# Check if the busybox directory does not exist
cd "$OUTDIR"
# Clone the busybox repository if it does not exist
# Filesystem hierarchy created is filled with content from the busy box
# Single binary that implements essential Linux programs
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git
    cd busybox
    # Checkout the specified version of busybox
    git checkout ${BUSYBOX_VERSION}
    #using  to clean the source tree and  to create a default configuration.
    # TODO:  Configure busybox
    # we follow the steps near similar to kernel build like discclean and defconfig 
	make distclean
	make defconfig
#Navigate to busybox if it exists
else
    cd busybox
fi

# TODO: Make and install busybox and we mention architecture and cross compile 
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
# We specify the location of root directory where we copy all the files and install it
# This installation also takes care of the symlinks to be created.
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

# Now Change to the rootfs directory for the library dependencies needed.
# We now find the library dependencies of the busybox and add them into our rootfile system.
# readelf is based on crosscompile.we thus look at program intrepreter which runs our busybox executable.
cd "${OUTDIR}"/rootfs
echo "Library dependencies"
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# TODO: Add library dependencies to rootfs
# Obtain the sysroot path using the GCC print-sysroot option
#These decides the applications we gonna be using. and PATH_LIBRARY shows path where we can find our libraries downloaded.
# we place these library dependencies  in root file system after locating them  in sys-root .
cd "${OUTDIR}"/rootfs
PATH_LIBRARY=$(aarch64-none-linux-gnu-gcc -print-sysroot)
# Copy libraries to the root filesystem.
cp "${PATH_LIBRARY}/lib/ld-linux-aarch64.so.1" "${OUTDIR}/rootfs/lib"
cp "${PATH_LIBRARY}/lib64/libm.so.6" "${OUTDIR}/rootfs/lib64"
cp "${PATH_LIBRARY}/lib64/libresolv.so.2" "${OUTDIR}/rootfs/lib64"
cp "${PATH_LIBRARY}/lib64/libc.so.6" "${OUTDIR}/rootfs/lib64"

# TODO: Make device nodes
# Create device nodes for null and console in the /dev directory
# Null device which provides 0 at place where content is unused.
# Console device to interact with terminal.
# c here specifies char.  major and minor representations are shown.
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 600 dev/console c 5 1

# TODO: Clean and build the writer utility
# Change to the finder-app directory and clean and build the writer utility
cd /home/aneesh/courses/aesd/assignment-2-aneesh1298/finder-app
make clean
make CROSS_COMPILE=aarch64-none-linux-gnu-
# Copy the built writer utility to the /home directory in the root filesystem
cp writer ${OUTDIR}/rootfs/home

# TODO: Copy the finder related scripts and executables to the /home directory
# on the target rootfs
# Copy finder scripts, autorun script, and configuration files to the /home directory
cp finder.sh finder-test.sh autorun-qemu.sh "${OUTDIR}/rootfs/home"
cp conf/username.txt conf/assignment.txt "${OUTDIR}/rootfs/home/conf"


# TODO: Chown the root directory
# Change ownership of the root directory and its contents to root:root
cd "${OUTDIR}"/rootfs
sudo chown -R root:root *

# TODO: Create initramfs.cpio.gz
# Create a compressed initramfs archive for QEMU boot. Set extracted into RAM for file system.
# Disc image loaded into ram by bootloader.
# THis cpio bundles content of rootfile system and creates .cpio file gziped  and qemu extracts that into a ram disc.
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd "${OUTDIR}"
gzip -f initramfs.cpio

