CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_GNU_SOURCE
SRCDIR = src
OBJDIR = obj
TESTDIR = tests
TARGET = sandbox

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean test install

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(OBJDIR)
	$(CC) $(OBJECTS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

test: $(TARGET)
	@echo "Running tests..."
	python3 $(TESTDIR)/test_basic.py
	python3 $(TESTDIR)/test_filesystem.py
	python3 $(TESTDIR)/test_restrictions.py

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

.PHONY: setup-test-env
setup-test-env:
	mkdir -p $(TESTDIR)/test_data/read_only
	mkdir -p $(TESTDIR)/test_data/read_write
	mkdir -p $(TESTDIR)/test_data/executables
	echo "This is a read-only test file" > $(TESTDIR)/test_data/read_only/test.txt
	echo "This is a writable test file" > $(TESTDIR)/test_data/read_write/writable.txt
	echo '#!/usr/bin/env python3\nprint("Hello from sandboxed script!")' > $(TESTDIR)/test_data/executables/test_script.py
	chmod +x $(TESTDIR)/test_data/executables/test_script.py
