BUILD_UWIFI=0
OPENWRT=0

INCLUDES=-I.

LDLIBS+=-luwifi
UWIFI_DEP=

ifeq ($(BUILD_UWIFI),1)
	UWIFI_DEP=./uwifi/lib/libuwifi.so.1
	LDFLAGS+=-L./uwifi/lib/
	INCLUDES+=-I./uwifi/include
endif

ifeq ($(OPENWRT),1)
	LDLIBS += -lradiotap
	LDLIBS += -lnl-tiny
endif

all: udpfwduwifi chancycler

./libuwifi/Makefile:
	git submodule update --init --recursive

./uwifi/lib/libuwifi.so.1: ./libuwifi/Makefile
	$(MAKE) -C libuwifi DEBUG=0 PLATFORM=linux
	-mkdir -p ./uwifi/include
	-mkdir -p ./uwifi/lib
	cp -r ./libuwifi/include/uwifi ./uwifi/include/
	cp ./libuwifi/linux/*.h ./uwifi/include/uwifi
	cp -a ./libuwifi/build/libuwifi.so* ./uwifi/lib/

udpfwduwifi.o: udpfwduwifi.c duples.h $(UWIFI_DEP)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

udpfwduwifi: udpfwduwifi.o 
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

chancycler.o: chancycler.c $(UWIFI_DEP)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

chancycler: chancycler.o 
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean-duples:
	rm -f *.o
	rm -f udpfwduwifi
	rm -f chancycler

clean-uwifi:
	$(MAKE) -C libuwifi clean
	rm -rf uwifi

clean: clean-duples clean-uwifi
