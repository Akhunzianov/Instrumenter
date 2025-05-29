#pragma once 

/**
 * @file Disassembler.hpp
 * @brief Instruction disassembler based on Capstone for analyzing code and extracting call information.
 *
 * Provides disassembly of instruction streams and identification of `call` instructions.
 * Stores results in a map and extracts metadata into `call_t` structures.
 */

#include <vector> 
#include <map> 
#include <unordered_map> 
#include <link.h>
#include <string>
#include <capstone/capstone.h> 

#include "Parser.hpp"
#include "Breakpointer.hpp"

/**
 * @brief Disassembles binary code and detects function calls.
 *
 * Uses Capstone to decode instruction streams and extract information
 * about calls. The class maintains a map of disassembled instructions and
 * populates a shared table of function call metadata (`calls_ht`).
 */
class Disassembler {
public:
    /**
     * @brief Constructs a disassembler for a given architecture.
     * 
     * @param arch Architecture type (e.g., X86_64).
     * @param calls Reference to the shared call table to populate.
     */
    Disassembler(ArchTypes arch, std::unordered_map<std::intptr_t, call_t>& calls) : archType(arch), calls_ht(calls) {} 

    /**
     * @brief Disassembles code and identifies `call` instructions.
     *
     * Populates the call table with data such as call address, target, and return address.
     * Prints error message anh exits on failure.
     *
     * @param code Pointer to the code region to disassemble.
     * @param size Number of bytes to disassemble.
     * @param code_entry Virtual address corresponding to the start of the code.
     * @param print_ins Whether to print disassembled instructions to stdout.
     */
    void call_disasm(uint8_t* code, int32_t size, std::intptr_t code_entry, bool print_ins);

    /**
     * @brief Performs full instruction disassembly.
     *
     * Stores each disassembled instruction in an internal map.
     * Prints error message anh exits on failure.
     *
     * @param code Pointer to the code region to disassemble.
     * @param size Size of code buffer.
     * @param code_entry Virtual address corresponding to the start of the code.
     * @param print_ins Whether to print disassembled instructions to stdout.
     */
    void ins_disasm(uint8_t* code, int32_t size, std::intptr_t code_entry, bool print_ins);

    /**
     * @brief Populates a `call_t` structure from a disassembled `call` instruction.
     *
     * Extracts call address, target address (if resolvable), and return address.
     *
     * @param insn The `call` instruction.
     * @param next_insn The next instruction (used to infer return address).
     * @param print If true, prints the instruction.
     */
    void call_generator(cs_insn &insn, cs_insn &next_insn, bool print); 

private:
    /**
     * @brief Prints a disassembled instruction in a readable format.
     *
     * @param disassembled_ins Instruction structure from Capstone.
     */
    void print_disassembled_ins(cs_insn &disassembled_ins);

    
    std::map<std::intptr_t, cs_insn> disassm_ins; // Map of address → disassembled instruction.
    std::unordered_map<std::intptr_t, call_t>& calls_ht; // Shared table of function calls.
    ArchTypes archType; // Architecture type for disassembly (e.g., X86_64).
};

