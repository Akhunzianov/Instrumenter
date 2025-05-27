#pragma once

#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <cmath>
#include <stdexcept>
#include <vector>
#include <utility>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <iostream>
#include <iomanip> 
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "Parser.hpp"
#include "ArchUtils.hpp"

class Instrument {
public:
    Instrument(std::unique_ptr<Parser> p) : real_parser(std::move(p)) {}

    // void load(const std::string& path, const std::string& out_path) override { real_parser->load(path, out_path); }
    // std::vector<Symbol> get_symbols() const override { return real_parser->get_symbols(); }
    // std::vector<Section> get_sections() const override { return real_parser->get_sections(); }
    // std::vector<Segment> get_segments() const override { return real_parser->get_segments(); }
    // std::vector<Relocation> get_relocations() const override { return real_parser->get_relocations(); }
    // void add_section(const std::string& name, const uint8_t* data, size_t len, uint64_t vaddr, uint8_t flags) override { 
    //     real_parser->add_section(name, data, len, vaddr, flags); 
    // };
    // void sync_map_file() override { real_parser->sync_map_file(); }
    // std::vector<Symbol> get_functions() const override { return real_parser->get_functions(); }
    // uint64_t get_function_vaddr(Symbol func) const override { return real_parser->get_function_vaddr(func); }
    // uint8_t* get_function_ptr(const Symbol &func) const override { return real_parser->get_function_ptr(func); };
    // uint64_t get_vacant_vaddr() const override { return real_parser->get_vacant_vaddr(); }
    // uint8_t* get_prog_mmap() const { return real_parser->prog_mmap; }

    void instrument_functions();
    
private:
    // size_t get_prologue_size(uint8_t* code, size_t max_len);
    std::vector<uint8_t> make_front_trampoline(uint32_t func_id, uint64_t handler_addr, uint64_t tramp_addr, uint64_t ret_addr); 
    std::vector<uint8_t> make_back_trampoline(uint32_t func_id, uint64_t handler_addr, uint64_t tramp_addr, uint64_t ret_addr); 
    std::pair<std::vector<uint8_t>, size_t> rewrite_prolog(uint8_t* func_ptr, uint8_t* tramp_addr);
    void allocate_data_section(uint64_t base_vaddr);
    std::vector<uint8_t> make_event_handler(uint64_t data_base, int32_t threshold, int32_t out_fd);

    std::unique_ptr<Parser> real_parser;
    std::vector<Symbol> functions;
};