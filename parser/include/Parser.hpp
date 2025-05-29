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
    size_t prog_size;
    uint8_t* prog_mmap;

    virtual ~Parser() = default;
    virtual void load(const std::string& path) = 0;
    virtual std::vector<Section>& get_sections() const = 0;
    virtual std::vector<Segment>& get_segments() const = 0;
    virtual std::vector<Symbol>& get_symbols() const = 0;
    virtual std::vector<Relocation>& get_relocations() const = 0;
    virtual std::vector<Symbol>& get_functions() const = 0;
    virtual uint64_t get_function_vaddr(Symbol func) const = 0;
    virtual uint8_t* get_function_ptr(const Symbol &func) const = 0;
    virtual uint64_t get_vacant_vaddr() const = 0;
    virtual uint64_t get_code_start_vaddr() const = 0;

};

std::unique_ptr<Parser> createParser(const std::string& path);
