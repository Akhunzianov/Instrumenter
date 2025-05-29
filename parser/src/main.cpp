#include "Parser.hpp"
#include <iostream>
#include <iomanip>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: parser <path-to-in-binary>\n";
        return 1;
    }

    try {
        auto parser = createParser(argv[1]);
        parser->load(argv[1]);

        // Print sections
        std::cout << "Sections:\n";
        for (const auto& sec : parser->get_sections()) {
            std::cout << "  " << sec.name << " @0x" << std::hex << sec.addr << std::dec << "\n";
            if (!sec.extra.empty()) {
                std::cout << "    Extra: ";
                for (const auto& kv : sec.extra)
                    std::cout << kv.first << "=" << kv.second << " ";
                std::cout << "\n";
            }
        }

        // Print segments
        std::cout << "\nSegments:\n";
        for (const auto& seg : parser->get_segments()) {
            std::cout << "  Type: " << seg.type << ", Flags: " << seg.flags << "\n";
            std::cout << "    Offset: 0x" << std::hex << seg.offset 
                      << ", VMA: 0x" << seg.vma << ", LMA: 0x" << seg.lma 
                      << std::dec << "\n";
            std::cout << "    Filesize: " << seg.filesize << ", Memsize: " << seg.memsize << "\n";
            if (!seg.extra.empty()) {
                std::cout << "    Extra: ";
                for (const auto& kv : seg.extra)
                    std::cout << kv.first << "=" << kv.second << " ";
                std::cout << "\n";
            }
        }

        // Print symbols
        std::cout << "\nSymbols:\n";
        for (const auto& sym : parser->get_symbols()) {
            std::cout << "  " << sym.name << " Value: 0x" << std::hex << sym.value << std::dec 
                      << ", Size: " << sym.size << "\n";
            std::cout << "    Type: " << sym.type << ", Bind: " << sym.bind 
                      << ", Visibility: " << sym.visibility << "\n";
            if (!sym.extra.empty()) {
                std::cout << "    Extra: ";
                for (const auto& kv : sym.extra)
                    std::cout << kv.first << "=" << kv.second << " ";
                std::cout << "\n";
            }
        }

        // Print relocations
        std::cout << "\nRelocations:\n";
        for (const auto& rel : parser->get_relocations()) {
            std::cout << "  Offset: 0x" << std::hex << rel.offset << std::dec 
                      << ", Info: 0x" << std::hex << rel.info << std::dec << "\n";
            std::cout << "    Type: " << rel.type << ", Symbol: " << rel.symbol_name << "\n";
            if (!rel.extra.empty()) {
                std::cout << "    Extra: ";
                for (const auto& kv : rel.extra)
                    std::cout << kv.first << "=" << kv.second << " ";
                std::cout << "\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 2;
    }
    return 0;
}
