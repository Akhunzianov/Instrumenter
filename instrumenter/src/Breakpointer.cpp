#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <inttypes.h> 

#include "Breakpointer.hpp"
#include "ArchUtils.hpp"

void Breakpointer::set_prog_pid(pid_t pid) {
    prog_pid = pid;
}

void Breakpointer::set_func_breakpoint(std::intptr_t &func_vaddr) {
    if (breakpoints_ht.count(func_vaddr)) {
        auto &bp = breakpoints_ht[func_vaddr];
        bp.is_func_addr = true;
    } 
    else {
        breakpoint_t bp;
        bp.bp_addr = func_vaddr;
        bp.is_func_addr = true;
        enable_breakpoint(prog_pid, bp);
        breakpoints_ht[func_vaddr] = bp;
    } 
}

void Breakpointer::set_call_breakpoint(std::intptr_t &call_address, std::intptr_t &call_return_address) {
    if (breakpoints_ht.count(call_address)) {
        auto &bp = breakpoints_ht[call_address];
        bp.is_call_caller_addr = true;
        bp.call_caller_addr = call_address;
    } 
    else {
        breakpoint_t bp;
        bp.bp_addr = call_address;
        bp.is_call_caller_addr = true;
        bp.call_caller_addr = call_address;
        enable_breakpoint(prog_pid, bp);
        breakpoints_ht[call_address] = bp;
    } 

    if (call_return_address == 0)
        return;

    if (breakpoints_ht.count(call_return_address)) {
        auto &bp = breakpoints_ht[call_return_address];
        bp.is_call_return_addr = true;
        bp.call_return_caller_addr = call_address;
    }
    else {
        breakpoint_t bp;
        bp.bp_addr = call_return_address;
        bp.is_call_return_addr = true;
        bp.call_return_caller_addr = call_address;
        enable_breakpoint(prog_pid, bp);
        breakpoints_ht[call_return_address] = bp;
    }  
}

extern "C" void __attribute__((weak)) clean_up_ptrace(pid_t pid) {
    return;
}

pid_t Breakpointer::wait_signal() {
    int status = 0;
    int opts = 0;
    prog_pid = waitpid(prog_pid, &status, opts);
    if (WIFEXITED(status) || (WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL)) {
      std::cout << "[+] process " << prog_pid << " terminated" << std::endl;
      clean_up_ptrace(prog_pid);
      return 0;
    }
    return prog_pid;
}

extern "C" void __attribute__((weak)) on_breakpoint_ptrace(pid_t pid, breakpoint_t& bp) {
    return;
}

void Breakpointer::step_over_breakpoint(std::unordered_map<std::intptr_t, int>& func_ht, std::vector<Symbol>& functions) {
    auto bp_prog_counter = get_program_counter(prog_pid) - 1;
    if (breakpoints_ht.count(bp_prog_counter)) {
        auto& bp = breakpoints_ht[bp_prog_counter];
        on_breakpoint_ptrace(prog_pid, bp);
        if (bp.enabled) {
            printf("breakpoint at [0x%" PRIx64 "] ", bp.bp_addr);
            if (bp.is_call_return_addr) {
                auto &call = calls_ht[bp.call_return_caller_addr];
                std::cout << "return: " << call.call_name << " ";
            }
            if (bp.is_call_caller_addr) {
                auto &call = calls_ht[bp.call_caller_addr];
                std::cout << "  call: " << call.call_name << " ";
            }
            if (bp.is_func_addr) {
                auto &sym = functions[func_ht[bp.bp_addr]];
                std::cout << "  call: " << sym.name << " ";
		if (print_regs)
		    print_registers(prog_pid);
            }
            printf("\n");
            auto previous_prog_counter = bp_prog_counter;
            set_program_counter(prog_pid, previous_prog_counter);
            disable_breakpoint(prog_pid, bp);
            ptrace(PTRACE_SINGLESTEP, prog_pid, nullptr, nullptr);
            if (wait_signal() == 0)
	        exit(0);
            enable_breakpoint(prog_pid, bp);
        }
  } 
}

std::unordered_map<std::intptr_t, call_t>& Breakpointer::get_calls_ht() {
    return calls_ht;
}

void Breakpointer::set_print_regs(bool enable) {
    print_regs = enable;
}

bool Breakpointer::get_print_regs() {
    return print_regs;
}

