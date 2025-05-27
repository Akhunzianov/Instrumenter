.PHONY: all clean ftrace profiler

all:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
	cmake --build build

clean:
	rm -rf build

parser: all
	@./build/parser/parser_exec $(IN) $(OUT)

instrumenter: all
	@./build/instrumenter/instrumenter_exec $(IN) $(OUT)

reader: all
	@./build/reader/reader_exec $(IN) $(OUT)