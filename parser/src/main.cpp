#include "Parser.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_set>


void print_help(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " <path-to-in-binary> [options]\n\n"
              << "Options:\n"
              << "  --no-sections       Do not display sections\n"
              << "  --no-segments       Do not display program segments\n"
              << "  --no-symbols        Do not display symbol table\n"
              << "  --no-relocs         Do not display relocations\n"
              << "  -h, --help          Show this help message\n";
}


bool has_flag(const std::unordered_set<std::string>& flags, const std::string& flag) {
    return flags.count(flag) > 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    std::string filepath = argv[1];

    std::unordered_set<std::string> flags;
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        }
        flags.insert(arg);
    }

    try {
        auto parser = createParser(filepath);
        parser->load(filepath);

        if (!has_flag(flags, "--no-sections")) {
            std::cout << "\nSections:\n\n";
            std::cout << std::left << std::setw(30) << "Name" 
                      << std::setw(18) << "Address" << "Extra\n\n";
            for (const auto& sec : parser->get_sections()) {
                std::cout << std::left << std::setw(30) << sec.name 
                          << "0x" << std::hex << std::setw(16) << sec.addr << std::dec;
                if (!sec.extra.empty()) {
                    for (const auto& kv : sec.extra)
                	std::cout << kv.first << "=" << std::left << std::setw(10) << kv.second << " ";
		        }
                std::cout << "\n";
            }
        }

        if (!has_flag(flags, "--no-segments")) {
            std::cout << "\nSegments:\n\n";
            std::cout << std::left << std::setw(20) << "Type" 
                      << std::setw(8) << "Flags"
                      << std::setw(12) << "Offset"
                      << std::setw(12) << "VMA"
                      << std::setw(12) << "LMA"
                      << std::setw(12) << "Filesz"
                      << std::setw(12) << "Memsz"
                      << "Extra\n\n";
            for (const auto& seg : parser->get_segments()) {
                std::cout << std::left << std::setw(20) << seg.type
                          << std::setw(8) << seg.flags
                          << "0x" << std::hex << std::setw(10) << seg.offset
                          << "0x" << std::setw(10) << seg.vma
                          << "0x" << std::setw(10) << seg.lma
                          << std::dec << std::setw(12) << seg.filesize
                          << std::setw(12) << seg.memsize;
                if (!seg.extra.empty()) {
                    for (const auto& kv : seg.extra)
                        std::cout << kv.first << "=" << std::left << std::setw(10) << kv.second << " ";
                }
                std::cout << "\n";
            }
        }

        if (!has_flag(flags, "--no-symbols")) {
            std::cout << "\nSymbols:\n\n";
            std::cout << std::left << std::setw(40) << "Name"
                      << std::setw(18) << "Value"
                      << std::setw(10) << "Size"
                      << std::setw(8) << "Type"
                      << std::setw(8) << "Bind"
                      << std::setw(12) << "Visibility"
                      << "Extra\n\n";
            for (const auto& sym : parser->get_symbols()) {
                std::cout << std::left << std::setw(40) << sym.name
                          << "0x" << std::hex << std::setw(16) << sym.value << std::dec
                          << std::setw(10) << sym.size
                          << std::setw(8) << sym.type
                          << std::setw(8) << sym.bind
                          << std::setw(12) << sym.visibility;
                if (!sym.extra.empty()) {
                    for (const auto& kv : sym.extra)
                        std::cout << kv.first << "=" << std::left << std::setw(10) << kv.second << " ";
                }
                std::cout << "\n";
            }
        }

        if (!has_flag(flags, "--no-relocs")) {
            std::cout << "\nRelocations:\n\n";
            std::cout << std::left << std::setw(18) << "Offset"
                      << std::setw(18) << "Info"
                      << std::setw(20) << "Type"
                      << std::setw(40) << "Symbol"
                      << "Extra\n\n";
            for (const auto& rel : parser->get_relocations()) {
                std::cout << "0x" << std::hex << std::setw(16) << rel.offset
                          << "0x" << std::setw(16) << rel.info << std::dec
                          << std::setw(20) << rel.type
                          << std::setw(40) << rel.symbol_name;
                if (!rel.extra.empty()) {
                    for (const auto& kv : rel.extra)
                        std::cout << kv.first << "=" << std::left << std::setw(10) << kv.second << " ";
                }
                std::cout << "\n";
            }
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 2;
    }

    return 0;
}
