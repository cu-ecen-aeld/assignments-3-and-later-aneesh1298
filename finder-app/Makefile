# This sets the CC variable to the compiler GCC
CC = gcc

# Compilation flags that consider all warnings as errors and most errors. 
CFLAGS = -Wall -Werror

# Cross-compiler prefix initialized to null string 
CROSS_COMPILE ?=

# Variable EXECUTABLE is set to the name writer.
EXECUTABLE = writer

# sets the OBJECT_FILE variable to the name of the object file writer.o
OBJECT_FILE = writer.o

# Default target: builds the executable
all: $(EXECUTABLE)

# Target to build the executable from the Object file with .o
# Automatic variable $@ replicates for the final executable writer
# Automatic variable $^ replicates for the object file writer.o, in general for all the pre-requisites
$(EXECUTABLE): $(OBJECT_FILE)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $^ -o $@

# Target to create the object file from the .c file
# Automatic variable $@ accounts for final target of .o file
# Automatic variable $< accounts for first pre-requisite ie write.c here
%.o: %.c
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c $< -o $@

# Target to clean up generated files
clean:
	rm -rf $(OBJECT_FILE) $(EXECUTABLE)

# Declare 'all' and 'clean' as phony targets
# To ensure they are always executed, regardless of whether there are actual files with the same names
.PHONY: all clean

