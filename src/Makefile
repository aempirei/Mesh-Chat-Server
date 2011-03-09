CC = gcc
CCC = g++
CCFLAGS = -Wall -lcrypt -O1
CFLAGS = -Wall
CPPFLAGS = -Wall -O1
TARGETS = meshchatd 

.PHONY: all wipe clean

all: $(TARGETS)

meshchatd: meshchatd.o user.o commands.o types.o network.o state.o config.o
	$(CCC) $(CCFLAGS) -ggdb -g -o $@ $^

clean:
	rm -f *.o *~

wipe: clean
	rm -f $(TARGETS)
