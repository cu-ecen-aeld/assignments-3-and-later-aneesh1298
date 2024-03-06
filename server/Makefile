CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror -g 
LDFLAGS ?= -pthread -lrt

all: aesdsocket

aesdsocket: aesdsocket.o
	$(CC) $^ $(LDFLAGS) -o $@

aesdsocket.o: aesdsocket.c
	$(CC) -c $^ $(CFLAGS) -o $@ 

clean:
	rm -f *.o aesdsocket
