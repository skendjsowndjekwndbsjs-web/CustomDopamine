CC = clang

CFLAGS = -I../.include -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=15.0 -Wno-deprecated-declarations -fno-stack-check -D_FORTIFY_SOURCE=0 -O2
LDFLAGS = -shared -Xlinker -add_split_seg_info
FILES = $(wildcard src/*.c src/*.S ../libjailbreak/src/jbclient_mach.c)
FILES_IOS15 = $(wildcard src/generated/ios15/*.c)

# Stripped for CustomDopamine: only the arm64 (no arm64e) / iOS15 target is
# needed for iPhone 7 Plus (A10) on iOS 15.8.5. Upstream Dopamine builds 6
# variants (arm64/arm64e x iOS15/iOS16-17/iOS18+); we only ship this one.
all: dyldhook_merge.arm64.iOS15.dylib

define CHECK_SELF_CONTAINED
	@UNDEF=$$(nm -u $(1) 2>/dev/null); \
	if [ -n "$$UNDEF" ]; then \
		echo "FAIL: $(1) has external symbols:"; \
		echo "$$UNDEF"; \
		exit 1; \
	fi
	@echo "PASS: $(1) is self-contained"
endef

dyldhook_merge.arm64.iOS15.dylib: $(FILES) $(FILES_IOS15)
	$(CC) -arch arm64 $(CFLAGS) -DIOS=15 $(LDFLAGS) -o $@ $^
	@ldid -Cadhoc -S $@
	$(call CHECK_SELF_CONTAINED,$@)

clean:
	@rm -f dyldhook_merge.arm64.iOS15.dylib
