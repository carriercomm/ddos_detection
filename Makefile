# Authors: Jan Neuzil
# Project: DDoS Detection
# jneuzil@isep.fr

# Learning track project

CC      = gcc
CFLAGS  = -Wall -pedantic -ggdb -std=c99 -O0
LDLIBS  = -lm
TARGETS = dir prog
OBJECTS = src/bin/cluster.o src/bin/graph.o src/bin/host.o src/bin/main.o src/bin/parser.o
DOXY    = doxygen
PROG	= ddos_detection
EXE     = ./ddos_detection

all: $(TARGETS)

./src/bin/%.o: ./src/%.c
	$(CC) $(CFLAGS) -c -o $@ $< $(LDLIBS)

src/bin/cluster.o: src/cluster.h src/graph.h src/host.h src/main.h
src/bin/graph.o: src/graph.h src/host.h src/main.h
src/bin/host.o: src/host.h src/main.h src/graph.h
src/bin/main.o: src/parser.h src/cluster.h src/graph.h src/host.h src/main.h
src/bin/parser.o: src/parser.h src/cluster.h src/graph.h src/host.h src/main.h

dir:
	mkdir -p src/bin

doc: 
	tar -xzf img.tar.gz
	$(DOXY)
	firefox doc/index.html &

prog: $(OBJECTS)
	$(CC) -o $(PROG) $(OBJECTS) $(LDLIBS)

clean:
	rm -rf doc
	rm -rf img
	rm -rf src/bin
	rm -f res/*
	rm -f $(EXE)

