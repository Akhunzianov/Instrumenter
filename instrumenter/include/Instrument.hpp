#pragma once

/**
 * @file Instrument.hpp
 * @brief Provides functionality to instrument and trace execution of ELF binaries using ptrace.
 *
 * The Instrument class forks and traces a target program, sets breakpoints on functions or call sites,
 * and monitors their execution via `ptrace`. It integrates with disassembly and symbol parsing logic.
 */

#include <unordered_map>

#include "Breakpointer.hpp"
#include "Parser.hpp"


/**
 * @brief Class responsible for managing instrumentation of a traced binary.
 *
 * Launches the target program, attaches to it via `ptrace`, sets breakpoints based on parsed symbols
 * or disassembled calls, and handles runtime breakpoint events.
 */
class Instrument {
public:
    /**
     * @brief Constructs an Instrument object with parser and breakpoint manager.
     *
     * @param p Unique pointer to a Parser instance.
     * @param bp Unique pointer to a Breakpointer instance.
     */
    Instrument(std::unique_ptr<Parser> p, std::unique_ptr<Breakpointer> bp) : real_parser(std::move(p)), real_breakpointer(std::move(bp)) {}

    /**
     * @brief Starts instrumentation: forks the program and handles setup + trace loop.
     *
     * @param argc Argument count from `main`.
     * @param argv Argument vector from `main`.
     */
    void start_instrument(int argc, char* argv[]);
    
private:
    /**
     * @brief Initializes breakpoints either from symbols or via disassembly.
     *
     * Called after program is loaded and ready for tracing.
     * It gathers all the addresses where breakpoints will take place.
     * If file have symbolic information than breakpoints are set where these functions start.
     * Otherwise, this function finds calls instances via Disassembler and marks them as bps.
     * @warning If you are planning of moifying this function dont 
     */
    void init_breakpoints();

    /**
     * @brief Executes the traced program (child process).
     *
     * Sets up `ptrace`, prctl death signal, and calls `execvp`.
     *
     * @param cmd Argument vector to execute.
     */
    void run_program(char* cmd[]);

    /**
     * @brief Handles initial tracing logic from parent after `fork()`.
     *
     * Waits for the child to be ready, sets ptrace flags, and initializes breakpoints.
     */
    void run_handler();

    /**
     * @brief Enters the main tracing loop after breakpoints are set.
     *
     * Continuously resumes execution and handles breakpoints as they are hit.
     */
    void continue_exec();

    /**
     * @brief Calculates the base virtual address of the loaded code segment (PIE offset).
     *
     * Parses `/proc/[pid]/maps` to determine where the binary was loaded in memory.
     *
     * @param offset Code section start offset from ELF headers.
     * @return PIE-adjusted virtual address base.
     */
    std::uintptr_t get_code_base_vaddr(uint64_t offset);

    std::unique_ptr<Parser> real_parser;               // ELF parser instance.
    std::unique_ptr<Breakpointer> real_breakpointer;   // Breakpoint manager instance.

    pid_t prog_pid;                                    // PID of the traced child process.
    std::unordered_map<std::intptr_t, int> funcs_ht;   // Map of function addresses to symbol indices.
    std::uintptr_t vaddr_offset;                       // Offset between static and dynamic code base addresses.
};
