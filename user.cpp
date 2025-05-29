#include <cstdio>
#include <sys/ptrace.h>

#include "instrumenter/include/Breakpointer.hpp"

extern "C" void set_ptrace_flags(pid_t pid) {
    // printf("Custom ptrace set flags\n");
    long ptrace_opts;
    ptrace_opts = PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEEXEC|PTRACE_O_TRACEEXIT;
    ptrace(PTRACE_SETOPTIONS, pid, 0, ptrace_opts);
}

extern "C" void before_run_ptrace(pid_t pid) {
    // printf("Custom before run ptrace\n");
    return;
}

extern "C" void on_breakpoint_ptrace(pid_t pid, breakpoint_t& bp) {
    // printf("Custom on breakpoint ptrace\n");
    return;
}

extern "C" void clean_up_ptrace(pid_t pid) {
    // printf("Custom clean up ptrace\n");
    return;
}

