CC=clang
CFLAGS=-fPIC -shared -isysroot $(shell xcrun --sdk macosx --show-sdk-path)
IPATH=-I../../Include -I/usr/local/include

iokernelrw_krw_plugin.dylib: iokernelrw_krw_plugin.c
	$(CC) $(CFLAGS) $(IPATH) $^ -o $@ -framework IOKit -Wl,-bundle

.PHONY: install clean

install: iokernelrw_krw_plugin.dylib
	sudo mkdir -p /opt/libkrw/
	sudo cp iokernelrw_krw_plugin.dylib /opt/libkrw/

clean:
	rm -f iokernelrw_krw_plugin.dylib