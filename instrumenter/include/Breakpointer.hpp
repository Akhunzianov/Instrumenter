#pragma once

/**
 * @file Breakpointer.hpp
 * @brief Defines structures and a class for managing breakpoints and call tracking using ptrace.
 */

#include <unordered_map> 
#include <sys/user.h>
#include <string>
#include <vector>

#include "Parser.hpp"

/** @struct foreignstruct
 *  @brief Represents metadata for a single function call in the program.
 *  
 *  
 *  
 * 
 */
typedef struct {
    std::intptr_t call_addr = 0;        // Address of the `call` instruction.
    std::intptr_t call_target_addr = 0; // Target address of the call (if resolvable).
    bool call_target_resolved = false;  // Whether the target address has been resolved.
    std::intptr_t call_return_addr = 0; // Address immediately after the call (return point).
    std::string call_name;              // Name of the called function, if available.
} call_t;

/**
 * @brief Represents a software breakpoint with context about its purpose.
 */
typedef struct {
    std::intptr_t bp_addr = 0;             // Address where the breakpoint is set.
    uint8_t orig_data = 0;                 // Original byte at that address (to be restored).
    bool enabled = false;                  // Whether the breakpoint is currently enabled.

    bool is_func_addr = false;             // Breakpoint is at a function entry.
    bool is_call_caller_addr = false;      // Breakpoint is at a `call` instruction.
    std::intptr_t call_caller_addr = 0;    // Address of the corresponding `call`.

    bool is_call_return_addr = false;      // Breakpoint is at a return site of a call.
    std::intptr_t call_return_caller_addr = 0; // Associated call site address.
} breakpoint_t;

/**
 * @brief Handles dynamic breakpoint management for a traced program.
 *
 * Allows setting breakpoints on functions, calls, and returns.
 * Also handles stepping over breakpoints and printing register state.
 */
class Breakpointer {
public:
    /**
     * @brief Sets the PID of the process to be traced.
     * @param pid Process ID of the target program.
     */
    void set_prog_pid(pid_t pid);

    /**
     * @brief Sets a breakpoint at the start of a function.
     * @param func_vaddr Virtual address of the function entry point.
     */
    void set_func_breakpoint(std::intptr_t &func_vaddr);

    /**
     * @brief Sets breakpoints at the `call` site and corresponding return site.
     * @param call_address Address of the `call` instruction.
     * @param call_return_address Address where execution returns after the call.
     */
    void set_call_breakpoint(std::intptr_t &call_address, std::intptr_t &call_return_address);

    /**
     * @brief Waits for a signal (e.g., breakpoint hit, single step) from the traced process.
     *
     * Cleans up if the process exited or was killed.
     *
     * @return The PID of the signaled process, or 0 if terminated.
     */
    pid_t wait_signal();

    /**
     * @brief Steps over a triggered breakpoint and restores it afterward.
     *
     * Prints registers state if enabled.
     *
     * @param func_ht Map of function addresses to symbol indices.
     * @param functions Vector of parsed function symbols.
     */
    void step_over_breakpoint(std::unordered_map<std::intptr_t, int>& func_ht, std::vector<Symbol>& functions);

    /**
     * @brief Returns the internal table of all observed or instrumented calls.
     * @return Reference to the call hash table.
     */
    std::unordered_map<std::intptr_t, call_t>& get_calls_ht();

    /**
     * @brief Enables or disables printing of register state when hitting breakpoints.
     * @param enable `true` to enable, `false` to disable.
     */
    void set_print_regs(bool enable);

    /**
     * @brief Gets the current state of register printing.
     * @return `true` if enabled, `false` otherwise.
     */
    bool get_print_regs();

private:
    std::unordered_map<std::intptr_t, breakpoint_t> breakpoints_ht; // Active breakpoints table.
    std::unordered_map<std::intptr_t, call_t> calls_ht;             // Table of tracked function calls.
    pid_t prog_pid;                                                 // PID of the traced process.
    bool print_regs;                                                // Whether to print registers at breakpoints.
};

