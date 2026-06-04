CC = gcc
CFLAGS = -O2 -Wall -Werror
LDLIBS = -lcrypt
TARGET = bin/please
SRC = please.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

install: $(TARGET)
	sudo chown root:root $(TARGET)
	sudo chmod u+s $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all install clean