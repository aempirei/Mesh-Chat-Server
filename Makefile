CC = gcc
CCC = g++
CCFLAGS = -Wall -O1 -I. -lcrypt
CFLAGS = -Wall -O1 -I.
CPPFLAGS = -Wall -O1 -I. -g -ggdb
TARGETS = tchatd 

all: $(TARGETS)

tchatd.o: tchatd.hh

tchatd: tchatd.o
	$(CCC) $(CCFLAGS) -ggdb -g -o $@ $<

clean:
	rm -f *.o *~

wipe: clean
	rm -f $(TARGETS)
