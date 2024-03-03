# Makefile in the "server" directory

CC := $(CROSS_COMPILE)gcc
CFLAGS := -g -Wall -Werror
LDFLAGS ?= -pthread -lrt

TARGET := aesdsocket

all: $(TARGET)

$(TARGET): aesdsocket.o
	$(CC) $^ $(LDFLAGS) -o $@

aesdsocket.o: aesdsocket.c
	$(CC) $(CFLAGS) -c aesdsocket.c

clean:
	-rm -f *.o $(TARGET)

#######
