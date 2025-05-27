#pragma once

#include <vector>
#include <string>

#include "types.hpp"

enum FileTypes { ELF };
enum ArchTypes { X86_64 };

class Parser {
public:
    FileTypes fileType;
    ArchTypes archType = X86_64; // TODO: parse arch types
    std::string prog_path;
    std::string out_prog_path;
    size_t prog_size;
    uint8_t* prog_mmap;

    virtual ~Parser() = default;
    virtual void load(const std::string& path, const std::string& out_path) = 0;
    virtual std::vector<Section> get_sections() const = 0;
    virtual std::vector<Segment> get_segments() const = 0;
    virtual std::vector<Symbol> get_symbols() const = 0;
    virtual std::vector<Relocation> get_relocations() const = 0;
    virtual std::vector<Symbol> get_functions() const = 0;
    virtual void add_section(const std::string& name, const uint8_t* data, size_t len, uint64_t vaddr, uint8_t flags) = 0;
    virtual void sync_map_file() = 0;
    virtual uint64_t get_function_vaddr(Symbol func) const = 0;
    virtual uint8_t* get_function_ptr(const Symbol &func) const = 0;
    virtual uint64_t get_vacant_vaddr() const = 0;

};

std::unique_ptr<Parser> createParser(const std::string& path);
