#include "Instrument.hpp"
#include "ArchUtils.hpp"
#include "Disassembler.hpp"

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
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fstream>
#include <sstream>
#include <sys/types.h>

void Instrument::start_instrument(int argc, char* argv[]) {
    prog_pid = fork();
    real_breakpointer->set_prog_pid(prog_pid);
    if (prog_pid == -1) {
        perror("start_instrument: fork error\n");
        exit(-1);
    }
    if (prog_pid == 0)
        run_program(argv + 1);
    else    
        run_handler();
}

void Instrument::run_program(char* cmd[]) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        perror("run_program: ptrace error\n");
        exit(-1);
    }
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    execvp(cmd[0], cmd);
}

void Instrument::run_handler() {
    prog_pid = real_breakpointer->wait_signal();

    long ptrace_opts;
    ptrace_opts = PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT;
    ptrace(PTRACE_SETOPTIONS, prog_pid, 0, ptrace_opts);
    init_breakpoints();
}

void Instrument::init_breakpoints() {
    auto& relocations = real_parser->get_relocations();
    auto& symbols = real_parser->get_symbols();
    auto& functions = real_parser->get_functions();

    vaddr_offset = get_code_base_vaddr(real_parser->get_code_start_vaddr());

    std::unordered_map<uint64_t, Relocation> rels_ht;
    for (auto &rel: relocations) 
        rels_ht[rel.addr + vaddr_offset] = rel;

    if (functions.size()) {
        for (int i = 0; i < functions.size(); ++i) {
            auto& func = functions[i];
	    std::intptr_t func_vaddr = real_parser->get_function_vaddr(func) + vaddr_offset;
            funcs_ht[func_vaddr] = i;
            real_breakpointer->set_func_breakpoint(func_vaddr);
        }
    }
    else {
        uint8_t* text_code;
        std::intptr_t text_code_entry;
        long text_code_size;

        Elf64_Ehdr *ehdr = (Elf64_Ehdr*)(real_parser->prog_mmap);
        text_code_entry = ehdr->e_entry;
        auto& segs = real_parser->get_segments();
        for(auto &seg: segs) {
            if(seg.type == "LOAD" && seg.flags == "RE") {
                text_code = &(real_parser->prog_mmap)[text_code_entry - seg.vma];
                text_code_size = seg.memsize;
                break;
            }
        }
        Disassembler diser = Disassembler(real_parser->archType, real_breakpointer->get_calls_ht());
        diser.call_disasm(text_code, text_code_size, text_code_entry, false);

        for (auto &call_map: real_breakpointer->get_calls_ht()) {
            auto &call = call_map.second;
            if ((!call.call_target_resolved) || (call.call_target_addr== 0))
                continue;
            if (rels_ht.count(call.call_target_addr))
                continue;
            else
                call.call_name = "f_" + std::to_string(call.call_target_addr);
            auto nullintptr = (std::intptr_t)0;
            real_breakpointer->set_call_breakpoint(call.call_addr, nullintptr);
        }
    }
    continue_exec();
}


void Instrument::continue_exec() {
    while (true) { 
        ptrace(PTRACE_CONT, prog_pid, nullptr, nullptr);
        real_breakpointer->wait_signal();
        real_breakpointer->step_over_breakpoint(funcs_ht, real_parser->get_functions());
    }
}

std::uintptr_t Instrument::get_code_base_vaddr(uint64_t offset) {
    std::ifstream maps("/proc/" + std::to_string(prog_pid) + "/maps");
    std::string line;
    std::vector<std::string> all_lines;
    uintptr_t base_address = 0;

    while (std::getline(maps, line)) {
        all_lines.push_back(line);
    }

    for (const auto& l : all_lines) {
        if (l.find("r-xp") != std::string::npos && l.find(real_parser->prog_path) != std::string::npos) {
            std::istringstream iss(l);
            std::string addr_range;
            iss >> addr_range;
            auto dash_pos = addr_range.find('-');
            std::string base_addr_str = addr_range.substr(0, dash_pos);
            base_address = std::stoul(base_addr_str, nullptr, 16);
            break;
        }
    }

    if (base_address == 0) {
        std::cerr << "Could not find base address for executable.\n";
        exit(1);
    }

    return base_address - offset;
}

