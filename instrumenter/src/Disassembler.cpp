#include <iostream>
#include <fcntl.h>      
#include <sys/stat.h> 
#include <sys/mman.h> 
#include <inttypes.h>

#include "Disassembler.hpp"
#include "Breakpointer.hpp"
#include "ArchUtils.hpp"


void Disassembler::call_disasm(uint8_t* code, int32_t size, std::intptr_t code_entry, bool print_ins) {  
    csh cs_handle;
    cs_insn *dis_ins;
    size_t cnt;
    auto [arch, mode] = get_capstone_config(archType);
    if (cs_open(arch, mode, &cs_handle) != CS_ERR_OK) {
        std::cout << "Initializing Capstone failed ..." << std::endl;
        exit(1);
    }
    cnt = cs_disasm(cs_handle, code, size, code_entry, 0, &dis_ins);
    if (cnt > 0) {
        size_t j;
        for (j = 0; j < cnt; j++) {
            if (print_ins)
                print_disassembled_ins(dis_ins[j]);
            if (std::string(dis_ins[j].mnemonic) != "call")
                continue;
            auto addr = (std::intptr_t)dis_ins[j].address;
            if (!calls_ht.count(addr)) {
                call_generator(dis_ins[j], dis_ins[j + 1], false);
            }
        }
        cs_free(dis_ins, cnt);
    } 
    else {
        std::cout << "ERROR: Failed to disassemble program ..." << std::endl;
        exit(1);
    }
    cs_close(&cs_handle);
}

void Disassembler::ins_disasm(uint8_t* code, int32_t size, std::intptr_t code_entry, bool print_ins) {
    csh cs_handle;
    cs_insn *dis_ins;
    size_t cnt;
    auto [arch, mode] = get_capstone_config(archType);
    if (cs_open(arch, mode, &cs_handle) != CS_ERR_OK) {
        std::cout << "Initializing Capstone failed ..." << std::endl;
        exit(1);
    }
    cnt = cs_disasm(cs_handle, code, size, code_entry, 0, &dis_ins);
    if (cnt > 0) {
        size_t j;
        for (j = 0; j < cnt; j++) {
            disassm_ins[dis_ins[j].address] = dis_ins[j];
            if (print_ins)
                print_disassembled_ins(dis_ins[j]);
        }
        cs_free(dis_ins, cnt);
    } 
    else {
        std::cout << "ERROR: Failed to disassemble program ..." << std::endl;
        exit(1);
    }
    cs_close(&cs_handle);
}

void Disassembler::print_disassembled_ins(cs_insn &disassembled_ins) {
    printf("0x%" PRIx64 ":\t%s\t\t%s\n", disassembled_ins.address, disassembled_ins.mnemonic, disassembled_ins.op_str);
}

void Disassembler::call_generator(cs_insn &insn, cs_insn &next_insn, bool print)  {
    call_t call;
    call.call_addr = insn.address;
    call.call_name = std::string(insn.op_str);
    call.call_target_resolved = false;
    try {
        std::intptr_t ptr = std::stol(std::string(insn.op_str), nullptr, 0);
        call.call_target_addr = ptr;
        call.call_target_resolved = true;
    } catch(...) {}
    try {
        call.call_return_addr = next_insn.address;
    } catch(...) {}
    calls_ht[call.call_addr] = call;  
    if (print)
         print_disassembled_ins(insn); 
}

