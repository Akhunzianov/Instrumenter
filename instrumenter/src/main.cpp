#include <iostream>
#include <memory>
#include "Instrument.hpp"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: ./program <path-to-in-binary> <path-to-out-binary>\n";
        return 1;
    }

    std::string path = argv[1];
    std::string out_path = argv[2];

    std::unique_ptr<Parser> parser = createParser(path);
    parser->load(path, out_path);

    Instrument instrument(std::move(parser));

    std::cout << "\nHi \n" << std::endl;

    instrument.instrument_functions();

    // using start_t = void(*)();
    // start_t start;
    // for (const auto& sym : instrument.get_functions()) {
    //     std::cout << "Function: " << sym.name << std::endl;
    //     if (sym.name == "main") {
    //         uint8_t* func_ptr = instrument.get_function_vaddr(sym);
    //         start = reinterpret_cast<start_t>(instrument.get_function_vaddr(sym));
    //     }
    // }

    // std::cout << "\nHi \n" << std::endl;

    // start();

    return 0;
}