CC = gcc
CFLAGS = -Wall -Wextra -std=c99
INCLUDE_DIR = include
SRC_DIR = src
TARGET = password_manager

SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
OBJ_FILES = $(SRC_FILES:.c=.o)

$(TARGET): $(OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

clean:
	rm -f $(OBJ_FILES) $(TARGET)

.PHONY: clean
