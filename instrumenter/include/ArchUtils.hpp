#pragma once

#include <cstdint>
#include <utility>
#include <stdexcept> 
#include <sys/user.h>
#include <capstone/capstone.h> 
#include <keystone/keystone.h>

#include "Parser.hpp"
#include "Breakpointer.hpp"

std::pair<cs_arch, cs_mode> get_capstone_config(ArchTypes archType);
std::pair<ks_arch, ks_mode> get_keystone_config(ArchTypes archType);

void set_program_counter(pid_t &pid, uint64_t &pc);
uint64_t get_program_counter(pid_t &pid);
user_regs_struct get_registers(pid_t &pid);
void enable_breakpoint(pid_t &pid, breakpoint_t &bp);
void disable_breakpoint(pid_t &pid, breakpoint_t &bp);
void print_registers(pid_t &pid);

