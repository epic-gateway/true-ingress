# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: cli_util.o

CFLAGS := -g -Wall

LIBBPF_DIR = ../libbpf/src/
CFLAGS += -I../headers

cli_util.o: cli_util.c cli_util.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
