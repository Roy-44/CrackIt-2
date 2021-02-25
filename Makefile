CC = gcc
UTILS = include.h
LIBS = -lmta_rand -lmta_crypt -lcrypto -lrt -pthread
SRCS := $(subst ./,,$(shell find . -maxdepth 1 -name "*.c"))
OBJS := $(patsubst %.c,%.out,$(SRCS))

all: $(OBJS)
	
%.out: %.c $(UTILS)
	$(CC) $< -o $@ $(LIBS) 
	
clean:
	find . -name "*.out" -exec rm {} \;
