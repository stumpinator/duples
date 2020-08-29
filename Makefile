BUILD_UWIFI=0
OPENWRT=0

INCLUDES = -I.
INCLUDES += -I./libuwifi/include/uwifi
INCLUDES += -I./libuwifi/linux/

LDLIBS += -luwifi
UWIFI_DEP=

ifeq ($(BUILD_UWIFI),1)
	UWIFI_DEP=./libuwifi/build/libuwifi.so.1
	LDFLAGS+=-L./libuwifi/build/
endif

ifeq ($(OPENWRT),1)
	LDLIBS += -lradiotap
	LDLIBS += -lnl-tiny
endif

all: udpfwduwifi chancycler

./libuwifi/Makefile:
	git submodule update --init --recursive

./libuwifi/build/libuwifi.so.1: ./libuwifi/Makefile
	$(MAKE) -C libuwifi DEBUG=0 PLATFORM=linux

udpfwduwifi.o: udpfwduwifi.c duples.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

udpfwduwifi: udpfwduwifi.o $(UWIFI_DEP)
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

chancycler.o: chancycler.c 
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

chancycler: chancycler.o $(UWIFI_DEP)
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean-duples:
	rm -f *.o
	rm -f udpfwduwifi
	rm -f chancycler

clean-uwifi:
	$(MAKE) -C libuwifi clean

clean: clean-duples clean-uwifi
