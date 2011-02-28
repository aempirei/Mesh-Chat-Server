CC = gcc
CCC = g++
CCFLAGS = -Wall -lcrypt -O1
CFLAGS = -Wall
CPPFLAGS = -Wall -O1
TARGETS = tchatd 

all: $(TARGETS)

tchatd.o: tchatd.hh

tchatd: tchatd.o user.o commands.o types.o
	$(CCC) $(CCFLAGS) -ggdb -g -o $@ $^

clean:
	rm -f *.o *~

wipe: clean
	rm -f $(TARGETS)
