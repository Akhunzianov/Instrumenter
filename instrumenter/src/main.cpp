#include <iostream>
#include <memory>
#include "Instrument.hpp"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ./program <path-to-in-binary> <args>\n";
        return 1;
    }

    std::string path = argv[1];

    std::unique_ptr<Parser> parser = createParser(path);
    parser->load(path);

    std::unique_ptr<Breakpointer> breakpointer = std::make_unique<Breakpointer>();

    Instrument instrument(std::move(parser), std::move(breakpointer));

    instrument.start_instrument(argc, argv);

    return 0;
}
