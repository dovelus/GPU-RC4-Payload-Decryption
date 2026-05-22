# GPU_Ldr_RC4 — clang on Windows (D3D11 compute-shader RC4)

CC      = clang
CFLAGS  = -O2 -Wall -Wextra -D_CRT_SECURE_NO_WARNINGS -Iinclude
LDLIBS  = -ld3d11 -ld3dcompiler

BUILD   = build
TARGET  = $(BUILD)/gpu_ldr_rc4.exe
SRCS    = src/main.c src/rc4.c
OBJS    = $(SRCS:src/%.c=$(BUILD)/%.o)
HEADERS = include/rc4.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILD)
	$(CC) -o $@ $^ $(LDLIBS)

$(BUILD)/%.o: src/%.c $(HEADERS) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD):
	-mkdir $(BUILD) 2>nul

clean:
	-rmdir /S /Q $(BUILD) 2>nul
