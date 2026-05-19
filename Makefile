SRCS := $(shell find . -name "*.cpp" -o -name "*.h" -o -name "*.hpp" -o -name "*.cc" -o -name "*.c")
HPP  := $(shell find . -name "*.hpp" -o -name "*.cpp")

.PHONY: format format-hpp/cpp

format:
	@if [ -z "$(SRCS)" ]; then \
		echo "[!] Files not found"; \
	else \
		clang-format -i $(SRCS); \
	fi

format-hpp/cpp:
	@if [ -z "$(HPP)" ]; then \
		echo "[!] Files not found"; \
	else \
		clang-format -i $(HPP); \
	fi
