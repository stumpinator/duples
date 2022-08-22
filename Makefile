BUILD_UWIFI=0
OPENWRT=0

INCLUDES=-I.

LDLIBS+=-luwifi
UWIFI_DEP=

ifeq ($(BUILD_UWIFI),1)
	UWIFI_DEP=./build/uwifi/lib/libuwifi.so.1
	LDFLAGS+=-L./build/uwifi/lib/
	INCLUDES+=-I./build/uwifi/include
endif

ifeq ($(OPENWRT),1)
	LDLIBS += -lradiotap
	LDLIBS += -lnl-tiny
endif

all: udpfwduwifi chancycler udpinjector udpstations

./libuwifi/Makefile:
	git submodule update --init --recursive

./build/uwifi/lib/libuwifi.so.1: ./libuwifi/Makefile
	$(MAKE) -C libuwifi DEBUG=0 PLATFORM=linux
	-mkdir -p ./build/uwifi/include
	-mkdir -p ./build/uwifi/lib
	cp -r ./libuwifi/include/uwifi ./build/uwifi/include/
	cp ./libuwifi/linux/*.h ./build/uwifi/include/uwifi
	cp -a ./libuwifi/build/libuwifi.so* ./build/uwifi/lib/
	ln -s ./build/uwifi/include/uwifi uwifi

udpfwduwifi.o: udpfwduwifi.c duples.h $(UWIFI_DEP)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

udpfwduwifi: udpfwduwifi.o 
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

udpinjector.o: udpinjector.c duples.h $(UWIFI_DEP)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

udpinjector: udpinjector.o 
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

udpstations.o: udpstations.c duples.h $(UWIFI_DEP)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

udpstations: udpstations.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

chancycler.o: chancycler.c $(UWIFI_DEP)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $< $(INCLUDES)

chancycler: chancycler.o 
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean-duples:
	rm -f *.o
	rm -f udpfwduwifi
	rm -f udpinjector
	rm -f chancycler
	rm -f udpstations

clean-uwifi:
	$(MAKE) -C libuwifi clean
	rm -rf build
	rm -f uwifi

clean: clean-duples clean-uwifi
