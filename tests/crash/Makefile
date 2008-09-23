CC=gcc
SOURCES=stack_overflow.c div_zero.c call_null.c abort.c fork.c execve.c invalid_write.c invalid_read.c socket_ipv4_tcp.c
PROGRAMS=$(patsubst %.c,%,$(SOURCES)) pthread
CFLAGS=-Wall -Wextra -Werror -O0 -g

all: $(PROGRAMS)

pthread: pthread.c
	$(CC) -o $@ $(CFLAGS) pthread.c -lpthread

clean:
	rm -f $(PROGRAMS)

