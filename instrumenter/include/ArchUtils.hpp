#pragma once

#include <cstdint>
#include <utility>
#include <stdexcept> 
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "Parser.hpp"

std::pair<cs_arch, cs_mode> get_capstone_config(ArchTypes archType);
std::pair<ks_arch, ks_mode> get_keystone_config(ArchTypes archType);
char* get_asm_front_trampoline(ArchTypes archType);
char* get_asm_back_trampoline(ArchTypes archType);
char* get_asm_prologue(ArchTypes archType);
char* get_asm_event(ArchTypes archType);
