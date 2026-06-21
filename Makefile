CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=gnu11
LDFLAGS = -ldl

TARGET = syscall_instrumentation
SRC = syscall_instrumentation.c

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
	rm -f *.o

# Install dependencies (Ubuntu/Debian)
deps:
	sudo apt-get update
	sudo apt-get install -y build-essential

# Run with strace to see syscalls
trace: $(TARGET)
	strace -c ./$(TARGET)

# Show disassembly
disasm: $(TARGET)
	objdump -d $(TARGET) | grep -A 10 "direct_syscall"

# Run Python demo (no compilation needed)
demo:
	python3 demo.py
