#include "ArchUtils.hpp"

#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <iostream>
#include <iomanip>

uint64_t get_program_counter(pid_t &pid) {
    user_regs_struct regs = get_registers(pid);

#ifdef __x86_64__
    return (uint64_t)regs.rip;
#else
    return (uint64_t)regs.eip;
#endif

}

void set_program_counter(pid_t &pid, uint64_t &pc) {
    user_regs_struct regs = get_registers(pid);

#ifdef __x86_64__
    regs.rip = pc;
#else
    regs.eip = pc;
#endif

    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

user_regs_struct get_registers(pid_t &pid) {
    struct user_regs_struct regs;
    long esp, eax, ebx, edx, ecx, esi, edi, eip;

#ifdef __x86_64__
    esp = regs.rsp;
    eip = regs.rip;
    eax = regs.rax;
    ebx = regs.rbx;
    ecx = regs.rcx;
    edx = regs.rdx;
    esi = regs.rsi;
    edi = regs.rdi;
#endif

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        perror("get_registers: PTRACE_GETREGS");
        exit(1);
    };
    return regs;
}

void enable_breakpoint(pid_t &pid, breakpoint_t &bp) {
    auto data = ptrace(PTRACE_PEEKDATA, pid, bp.bp_addr, nullptr);
    
#ifdef __x86_64__
    bp.orig_data = static_cast<uint8_t>(data & 0xff); 
    uint64_t int3 = 0xcc;
    uint64_t data_with_inter = ((data & ~0xff) | int3);
#endif

    ptrace(PTRACE_POKEDATA, pid, bp.bp_addr, data_with_inter);
    bp.enabled = true;
}

void disable_breakpoint(pid_t &pid, breakpoint_t &bp) {
    auto data = ptrace(PTRACE_PEEKDATA, pid, bp.bp_addr, nullptr);

#ifdef __x86_64__
    auto restored_data = ((data & ~0xff) | bp.orig_data);
#endif

    ptrace(PTRACE_POKEDATA, pid, bp.bp_addr, restored_data);
    bp.enabled = false;
}

void print_registers(pid_t &pid) {
    user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, nullptr, &regs) == -1) {
        perror("PTRACE_GETREGS");
        exit(1);
    }

    std::cout << "\n\n========== Register Dump (PID: " << pid << ") ==========\n";

#ifdef __x86_64__
    std::cout << std::setw(6) << "reg" << "   hex                  dec\n";
    std::cout << "----------------------------------------------\n";
    auto hexfmt = [](const char* name, uint64_t val) {
        std::cout << std::setw(6) << name << "   0x"
                  << std::setfill('0') << std::setw(16) << std::hex << val
                  << std::setfill(' ') << "   "
                  << std::dec << val << "\n";
    };
    hexfmt("RIP", regs.rip);
    hexfmt("RSP", regs.rsp);
    hexfmt("RBP", regs.rbp);
    hexfmt("RAX", regs.rax);
    hexfmt("RBX", regs.rbx);
    hexfmt("RCX", regs.rcx);
    hexfmt("RDX", regs.rdx);
    hexfmt("RSI", regs.rsi);
    hexfmt("RDI", regs.rdi);
    hexfmt("R8",  regs.r8);
    hexfmt("R9",  regs.r9);
    hexfmt("R10", regs.r10);
    hexfmt("R11", regs.r11);
    hexfmt("R12", regs.r12);
    hexfmt("R13", regs.r13);
    hexfmt("R14", regs.r14);
    hexfmt("R15", regs.r15);
    std::cout << "----------------------------------------------\n";
#endif

}


std::pair<cs_arch, cs_mode> get_capstone_config(ArchTypes archType) {
    switch (archType) {
	case X86_64:
	    return {CS_ARCH_X86, CS_MODE_64};
	    break;
        
	default:
	    throw std::invalid_argument("Unknown architecture");
            break;
    }
}

std::pair<ks_arch, ks_mode> get_keystone_config(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return {KS_ARCH_X86, KS_MODE_64};
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}

