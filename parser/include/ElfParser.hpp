#pragma once

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>  
#include <sys/stat.h> 
#include <sys/mman.h> 
#include <cstring>
#include <elf.h>

#include "Parser.hpp"
    
class ElfParser : public Parser {
public:
    void load(const std::string& path, const std::string& out_path) override;
    std::vector<Section> get_sections() const override;
    std::vector<Segment> get_segments() const override;
    std::vector<Symbol> get_symbols() const override;
    std::vector<Relocation> get_relocations() const override;
    std::vector<Symbol> get_functions() const override;
    void add_section(const std::string& name, const uint8_t* data, size_t len, uint64_t vaddr, uint8_t flags) override;
    void sync_map_file() override;
    uint64_t get_function_vaddr(Symbol func) const override;
    uint8_t* get_function_ptr(const Symbol &func) const override;
    uint64_t get_vacant_vaddr() const override;
    
private:
    std::string get_section_type(int type) const;
    std::string get_segment_type(uint32_t &type) const;
    std::string get_segment_flags(uint32_t &sflags) const;
    std::string get_symbol_type(uint8_t &type) const;
    std::string get_symbol_bind(uint8_t &bind) const;
    std::string get_symbol_visibility(uint8_t &vis) const;
    std::string get_symbol_index(uint16_t &ind) const;
    std::string get_relocation_type(uint64_t &type) const;
    std::intptr_t get_relocation_symbol_value(uint64_t &ind, std::vector<Symbol> &syms) const;
    std::string get_relocation_symbol_name(uint64_t &ind, std::vector<Symbol> &syms) const;

};

