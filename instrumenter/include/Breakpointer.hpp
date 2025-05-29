#pragma once

#include <unordered_map> 
#include <sys/user.h>
#include <string>
#include <vector>

#include "Parser.hpp"

typedef struct {
    std::intptr_t call_addr = 0; 
    std::intptr_t call_target_addr = 0; 
    bool call_target_resolved = false;
    std::intptr_t call_return_addr = 0; 
    std::string call_name;
} call_t;

typedef struct {
    std::intptr_t bp_addr = 0;
    uint8_t orig_data = 0;
    bool enabled = false;
    bool is_func_addr = false;
    bool is_call_caller_addr = false;
    std::intptr_t call_caller_addr = 0;
    bool is_call_return_addr = false;
    std::intptr_t call_return_caller_addr = 0; 
} breakpoint_t;

class Breakpointer {
public:
    void set_prog_pid(pid_t pid);
    void set_func_breakpoint(std::intptr_t &func_vaddr);
    void set_call_breakpoint(std::intptr_t &call_address, std::intptr_t &call_return_address);
    pid_t wait_signal();
    void step_over_breakpoint(std::unordered_map<std::intptr_t, int>& func_ht, std::vector<Symbol>& functions);
    std::unordered_map<std::intptr_t, call_t>& get_calls_ht();
    void set_print_regs(bool enable);
    bool get_print_regs();

private:
    std::unordered_map<std::intptr_t, breakpoint_t> breakpoints_ht;
    std::unordered_map<std::intptr_t, call_t> calls_ht;
    pid_t prog_pid;
    bool print_regs;
};

