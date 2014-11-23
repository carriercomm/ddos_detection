# Authors: Jan Neužil, Alexandre Joubert, Matthieu Caroy, Boris Mineau
# Project: Matrix
# jneuzil@isep.fr, ajoubert@isep.fr, mcarroy@isep.fr, bmineau@isep.fr

# Learning track project

CC      = gcc
CFLAGS  = -Wall -pedantic -ggdb -std=c99 -O0
LDLIBS  =
TARGETS = dir prog
OBJECTS = ./src/bin/ddos_detection.o
DOXY    = doxygen
PROG	= ddos_detection
EXE     = ./ddos_detection

all: $(TARGETS)

./src/bin/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c -o $@ $< $(LDLIBS)

./src/bin/$(PROG).o: ./src/$(PROG).h

dir:
	mkdir -p ./src/bin

doc: 
	tar -xzf img.tar.gz
	$(DOXY)
	firefox ./doc/index.html &

prog: ./src/bin/ddos_detection.o	
	$(CC) -o $(PROG) ./src/bin/$(PROG).o $(LDLIBS)

clean:
	rm -rf ./doc
	rm -rf ./img
	rm -rf ./src/bin
	rm -f ./res/*
	rm -f $(EXE)

