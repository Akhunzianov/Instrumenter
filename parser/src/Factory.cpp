#include <fstream>
#include <stdexcept>
#include <cstring>

#include "Parser.hpp"
#include "ElfParser.hpp"

std::unique_ptr<Parser> createParser(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) 
        throw std::runtime_error("Cannot open file: " + path);

    char magic[4]{};
    file.read(magic, sizeof(magic));
    if (!file) 
        throw std::runtime_error("Failed reading magic bytes");

    if (std::memcmp(magic, "\x7F""ELF", 4) == 0)
        return std::make_unique<ElfParser>();

    throw std::runtime_error("Unsupported binary format");
}