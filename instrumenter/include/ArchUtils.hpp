#pragma once

/**
 * @file ArchUtils.hpp
 * @brief Architecture-specific utilities for breakpointing and instrumentation.
 *
 * In order to add the support for new architerture to the project in all functions
 * from this file must be implemented the corresponding logic.
 */

#include <cstdint>
#include <utility>
#include <stdexcept> 
#include <sys/user.h>
#include <capstone/capstone.h> 
#include <keystone/keystone.h>

#include "Parser.hpp"
#include "Breakpointer.hpp"

/**
 * @brief Returns Capstone disassembler configuration for a given architecture.
 * 
 * @param archType Architecture type, determined in Parser (e.g., X86_64).
 * @return A pair of `cs_arch` and `cs_mode` values for initializing Capstone.
 * @throws std::invalid_argument If the architecture is unsupported.
 */
std::pair<cs_arch, cs_mode> get_capstone_config(ArchTypes archType);

/**
 * @brief Returns Keystone assembler configuration for a given architecture.
 * 
 * @param archType Architecture type, determined in Parser (e.g., X86_64).
 * @return A pair of `ks_arch` and `ks_mode` values for initializing Keystone.
 * @throws std::invalid_argument If the architecture is unsupported.
 */
std::pair<ks_arch, ks_mode> get_keystone_config(ArchTypes archType);

/**
 * @brief Sets the program counter (PC / RIP) to a specific value.
 *
 * @param pid Process ID of the traced process.
 * @param pc New value to set as the program counter.
 */
void set_program_counter(pid_t &pid, uint64_t &pc);

/**
 * @brief Retrieves the current value of the program counter (PC / RIP) of process with given PID.
 *
 * @param pid Process ID of the traced process.
 * @return Current value of the instruction pointer (RIP/EIP).
 */
uint64_t get_program_counter(pid_t &pid);

/**
 * @brief Fetches the current CPU register state of the given process.
 *
 * Prints error message anh exits on failure.
 * 
 * @param pid Process ID of the traced process.
 * @return `user_regs_struct` structure containing register values.
 */
user_regs_struct get_registers(pid_t &pid);

/**
 * @brief Enables a breakpoint by inserting an the corresponding instruction.
 *
 * Stores the original byte/s and replaces it with the breakpoint instruction.
 * On x86_64 inserts `int3` instruction (0xCC) on the first byte's place.
 *
 * @param pid Process ID of the traced process.
 * @param bp Reference to a breakpoint_t object describing the target address.
 * @warning This funcion is very platform depandent, inspect carefully how to implement it for new platforms.
 */
void enable_breakpoint(pid_t &pid, breakpoint_t &bp);

/**
 * @brief Disables a breakpoint by restoring the original byte/s.
 *
 * @param pid Process ID of the traced process.
 * @param bp Reference to the breakpoint_t object.
 * @warning This funcion is very platform depandent, inspect carefully how to implement it for new platforms.
 */
void disable_breakpoint(pid_t &pid, breakpoint_t &bp);

/**
 * @brief Prints the current register values of the given process.
 *
 * This is formatted output.
 *
 * @param pid Process ID of the traced process.
 */
void print_registers(pid_t &pid);

