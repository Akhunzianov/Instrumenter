.PHONY: all clean ftrace profiler

all:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
	cmake --build build

clean:
	rm -rf build
	rm -rf parser_exec
	rm -rf instrumenter_exec
