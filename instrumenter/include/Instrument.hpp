#pragma once

#include <unordered_map>

#include "Breakpointer.hpp"
#include "Parser.hpp"

class Instrument {
public:
    Instrument(std::unique_ptr<Parser> p, std::unique_ptr<Breakpointer> bp) : real_parser(std::move(p)), real_breakpointer(std::move(bp)) {}

    void start_instrument(int argc, char* argv[]);
    
private:
    void init_breakpoints();
    void run_program(char* cmd[]);
    void run_handler();
    void continue_exec();
    std::uintptr_t get_code_base_vaddr(uint64_t offset);

    std::unique_ptr<Parser> real_parser;
    std::unique_ptr<Breakpointer> real_breakpointer;
    pid_t prog_pid;
    std::unordered_map<std::intptr_t, int> funcs_ht;
    std::uintptr_t vaddr_offset;
};
