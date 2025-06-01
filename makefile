CC=gcc
CFLAGS=-g -Wall
LDFLAGS=-lssl -lcrypto -lcurl -ljansson -pthread -linih
EXECUTABLE=irc_website_bridge
SRC=irc_website_bridge.c

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(EXECUTABLE)