BPF_CLANG ?= clang
# Auto-detect the system include root; Termux uses a non-standard prefix.
BPF_SYSTEM_INCLUDE ?= $(shell for d in /usr/include /data/data/com.termux/files/usr/include; do [ -f "$$d/linux/bpf.h" ] && echo "$$d" && break; done)
# asm/types.h lives in a multiarch dir on Debian/Ubuntu (e.g. x86_64-linux-gnu)
# and in the Android arch dir on Termux.
BPF_MULTIARCH_INCLUDE ?= $(shell for d in \
	$(BPF_SYSTEM_INCLUDE)/x86_64-linux-gnu \
	$(BPF_SYSTEM_INCLUDE)/aarch64-linux-gnu \
	$(BPF_SYSTEM_INCLUDE)/arm-linux-gnueabihf \
	$(BPF_SYSTEM_INCLUDE)/i386-linux-gnu \
	$(BPF_SYSTEM_INCLUDE)/aarch64-linux-android \
	$(BPF_SYSTEM_INCLUDE)/x86_64-linux-android; do [ -f "$$d/asm/types.h" ] && echo "$$d" && break; done)
BPF_CFLAGS ?= -target bpfel -O2 -g0
BPF_INCLUDE_FLAGS := -Inative -I$(BPF_SYSTEM_INCLUDE)
ifneq (,$(wildcard $(BPF_MULTIARCH_INCLUDE)))
BPF_INCLUDE_FLAGS += -I$(BPF_MULTIARCH_INCLUDE)
endif

SOURCE := native/shared_network.bpf.c
OBJECT := native/shared_network.bpf.o

.PHONY: generate check clean

generate:
	@set -eu; \
	temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) \
		-c "$(SOURCE)" -o "$$temporary"; \
	mv "$$temporary" "$(OBJECT)"

check:
	@set -eu; \
	temporary="$$(mktemp "$(OBJECT).XXXXXX")"; \
	trap 'rm -f "$$temporary"' EXIT; \
	$(BPF_CLANG) $(BPF_CFLAGS) $(BPF_INCLUDE_FLAGS) \
		-c "$(SOURCE)" -o "$$temporary"; \
	if ! cmp -s "$(OBJECT)" "$$temporary"; then \
		echo "$(OBJECT) is stale; run 'make generate' in this directory" >&2; \
		exit 1; \
	fi

clean:
	rm -f "$(OBJECT)"
