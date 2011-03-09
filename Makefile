TARGETS = bin/meshchatd 
INSTALL_PATH = /usr/local/bin

.PHONY: all clean wipe src/meshchatd install

all: $(TARGETS)

src/meshchatd:
	( cd src ; make )

bin/meshchatd: src/meshchatd
	cp src/meshchatd $@

install: all
	install -m755 $(TARGETS) $(INSTALL_PATH)

clean:
	( cd src ; make clean )
	( cd bin ; make clean )

wipe:
	( cd src ; make wipe )
	( cd bin ; make wipe )
