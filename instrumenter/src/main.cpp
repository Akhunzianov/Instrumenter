#include <iostream>
#include <memory>
#include "Instrument.hpp"


void print_help(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options] <path-to-in-binary> <args>\n\n"
              << "Options:\n"
              << "  --print-regs        Print register values at breakpoints\n"
              << "  -h, --help          Show this help message\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./program [--print-regs] <path-to-in-binary> <args>\n";
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--help" || std::string(argv[i]) == "-h" ) {
            print_help(argv[0]);
            return 0;
        }
    }

    std::string path = argv[1];
    bool enable_print_regs = false;
    
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--print-regs") {
            enable_print_regs = true;
            path = argv[2];
        }
    }

    std::unique_ptr<Parser> parser = createParser(path);
    parser->load(path);

    std::unique_ptr<Breakpointer> breakpointer = std::make_unique<Breakpointer>();
    breakpointer->set_print_regs(enable_print_regs);

    Instrument instrument(std::move(parser), std::move(breakpointer));
    instrument.start_instrument(argc, argv);

    return 0;
}
