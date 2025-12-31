CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

ifeq ($(VERIFY), 0)
    CLIENT_CFLAGS += -DNO_VERIFY
endif

CLIENT = tls_client
SERVER = tls_server

CLIENT_SRC = tls_client.c
SERVER_SRC = tls_server.c

all: $(CLIENT) $(SERVER)

$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(CLIENT_CFLAGS) $(CLIENT_SRC) -o $(CLIENT) $(LDFLAGS)

$(SERVER): $(SERVER_SRC)
	$(CC) $(CFLAGS) $(SERVER_SRC) -o $(SERVER) $(LDFLAGS)

clean:
	rm -f $(CLIENT) $(SERVER)

.PHONY: all clean