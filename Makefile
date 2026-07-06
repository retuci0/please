CC      := gcc
CFLAGS  := -Wall -Wextra -O2
LDLIBS  := -lcrypt

OBJS := bin/please.o bin/config.o

bin/pls: $(OBJS) | bin
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

bin/%.o: src/%.c src/config.h | bin
	$(CC) $(CFLAGS) -c -o $@ $<

bin:
	mkdir -p bin

install: bin/pls
	install -o root -g root -m 4755 bin/pls /usr/local/bin/pls
	install -o root -g root -m 644 please.conf /etc/please.conf

clean:
	rm -f bin/*

.PHONY: install clean
