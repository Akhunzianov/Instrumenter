#pragma once 

#include <vector> 
#include <map> 
#include <unordered_map> 
#include <link.h>
#include <string>
#include <capstone/capstone.h> 

#include "Parser.hpp"
#include "Breakpointer.hpp"

class Disassembler {
public:
    Disassembler(ArchTypes arch, std::unordered_map<std::intptr_t, call_t>& calls) : archType(arch), calls_ht(calls) {} 
    void call_disasm(uint8_t* code, int32_t size, std::intptr_t code_entry, bool print_ins);
    void ins_disasm(uint8_t* code, int32_t size, std::intptr_t code_entry, bool print_ins);
    void call_generator(cs_insn &insn, cs_insn &next_insn, bool print); 

private:
    void print_disassembled_ins(cs_insn &disassembled_ins);
    std::map<std::intptr_t, cs_insn> disassm_ins;
    std::unordered_map<std::intptr_t, call_t>& calls_ht;
    ArchTypes archType;
};

