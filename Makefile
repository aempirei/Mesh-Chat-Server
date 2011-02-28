TARGETS = bin/tchatd 
INSTALL_PATH = /usr/local/bin

.PHONY: all clean wipe src/tchatd install

all: $(TARGETS)

src/tchatd:
	( cd src ; make )

bin/tchatd: src/tchatd
	cp src/tchatd $@

install: all
	install -m755 $(TARGETS) $(INSTALL_PATH)

clean:
	( cd src ; make clean )
	( cd bin ; make clean )

wipe:
	( cd src ; make wipe )
	( cd bin ; make wipe )
