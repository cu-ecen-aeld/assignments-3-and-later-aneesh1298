# Makefile in the "server" directory

CC := $(CROSS_COMPILE)gcc
CFLAGS := -g -Wall -Werror

TARGET := aesdsocket

all: $(TARGET)

$(TARGET): aesdsocket.o
	$(CC) $(CFLAGS) aesdsocket.o -o $(TARGET)

aesdsocket.o: aesdsocket.c
	$(CC) $(CFLAGS) -c aesdsocket.c

clean:
	-rm -f *.o $(TARGET)

