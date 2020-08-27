CC=gcc
PLATFORM=linux
DEBUG=0

IFLAGS = -I.
IFLAGS += -I./libuwifi/include/uwifi
IFLAGS += -I./libuwifi/linux/

LFLAGS = -luwifi
LFLAGS += -L./libuwifi/build/

all: udpfwduwifi chancycler

./libuwifi/Makefile:
	git submodule update --init --recursive

./libuwifi/build/libuwifi.so.1: ./libuwifi/Makefile
	$(MAKE) -C libuwifi DEBUG=$(DEBUG) PLATFORM=$(PLATFORM)

udpfwduwifi.o: udpfwduwifi.c duples.h ./libuwifi/build/libuwifi.so.1
	$(CC) -c -o $@ $< $(IFLAGS)

udpfwduwifi: udpfwduwifi.o
	$(CC) -o $@ $^ $(LFLAGS)

chancycler.o: chancycler.c ./libuwifi/build/libuwifi.so.1
	$(CC) -c -o $@ $< $(IFLAGS)

chancycler: chancycler.o
	$(CC) -o $@ $^ $(LFLAGS)

clean-duples:
	rm -f *.o
	rm -f udpfwduwifi
	rm -f chancycler

clean-uwifi:
	$(MAKE) -C libuwifi clean

clean: clean-duples clean-uwifi
