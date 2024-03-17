/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "linux/slab.h"
#include "linux/string.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Aneesh Gurram"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *my_dev;
    PDEBUG("open");
    my_dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = my_dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
     // As we didnt allocate anything I think nothing to be done.
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_buffer_entry *buffer = NULL;
    ssize_t entry_offset_byte_return = 0, buffer_cnt = 0; 
    if ( (filp == NULL) || (buf == NULL))
    {
        PDEBUG("ERROR: READ invalid ");
        return -EINVAL;
    }
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
     
    if(mutex_lock_interruptible(&aesd_device.lock) !=0)
    {
    	PDEBUG("ERROR: MUTEX lock ");
        return -EINTR;
    }
    buffer = aesd_circular_buffer_find_entry_offset_for_fpos(&aesd_device.buffer, *f_pos, &entry_offset_byte_return);
    if(buffer == NULL)
    {
        *f_pos = 0;
        goto error_handler;
    }
    buffer_cnt = buffer->size - entry_offset_byte_return;
    buffer_cnt = (buffer_cnt > count) ? count : buffer_cnt;
    *f_pos += buffer_cnt;
    //copies data buf
    if(copy_to_user(buf, buffer->buffptr+entry_offset_byte_return, buffer_cnt))
    {
        retval = -EFAULT;
        goto error_handler;
    }

    retval = buffer_cnt;
error_handler:
    mutex_unlock(&aesd_device.lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *my_dev = NULL;  
    const char *free_ptr = NULL;
    if ( (filp == NULL) || (buf == NULL))
    {
        PDEBUG("ERROR: WRITE invalid ");
        return -EINVAL;
    }
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    my_dev = filp->private_data;
    if(!my_dev)
    {
        return -EFAULT;
    }
    
    if(!(my_dev->entry.size))
    {
        my_dev->entry.buffptr = (char *)kmalloc(count, GFP_KERNEL);  // Allocate memory for circular buffer
    }
    else
    {
        my_dev->entry.buffptr = (char *)krealloc(my_dev->entry.buffptr, my_dev->entry.size + count, GFP_KERNEL); // Re-Allocate memory for circular buffer
    }
    if(!(my_dev->entry.buffptr))
    {
        retval = -ENOMEM;
    }
    
    if(0 != mutex_lock_interruptible(&aesd_device.lock))
    {
        return -EINTR;
    }  
    if (copy_from_user((void *)(my_dev->entry.buffptr + my_dev->entry.size), buf, count))
    {
    	retval = -EFAULT;
        PDEBUG("ERROR:copy_from_user retval=%zu", retval);
        goto error_handler;
    }
    retval=count;
    my_dev->entry.size += retval;
    if (dev->entry.buffptr[dev->entry.size-1] == '\n')
    {
        free_ptr = aesd_circular_buffer_add_entry(&dev->buffer, &dev->entry);
        /* free overwritten entry buffptr */
        if (free_ptr != NULL)
        {
            kfree(free_ptr);
            free_ptr = NULL;
        }
        /* reset working entry */
        dev->entry.buffptr = NULL;
        dev->entry.size = 0;
    }
error_handler:
    mutex_unlock(&aesd_device.lock);  // Release the mutex lock
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&(aesd_device.buffer));

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    int index = 0;
    struct aesd_buffer_entry *entry = NULL;
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    mutex_destroy(&aesd_device.lock);
    AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.buffer,index)
    {
        if (entry->buffptr !=NULL)
        {
            kfree(entry->buffptr);
            entry->buffptr = NULL;
        }
    }
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
