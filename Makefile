TARGETS = tchatd 

all: $(TARGETS)

tchatd.o: tchatd.hh

tchatd:
	( cd src ; make )
	cp src/tchatd bin

clean:
	( cd src ; make clean )
	( cd bin ; make clean )

wipe:
	( cd src ; make wipe )
	( cd bin ; make wipe )
