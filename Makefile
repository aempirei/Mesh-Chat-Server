CC = gcc
CCC = g++
CCFLAGS = -Wall -lcrypt -O2 -g -ggdb
CFLAGS = -Wall
CPPFLAGS = -Wall -O2 -g -ggdb
TARGETS = tchatd 

all: $(TARGETS)

tchatd.o: tchatd.hh

tchatd: tchatd.o user.o
	$(CCC) $(CCFLAGS) -ggdb -g -o $@ $^

clean:
	rm -f *.o *~

wipe: clean
	rm -f $(TARGETS)
