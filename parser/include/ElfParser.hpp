#pragma once

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <cstdlib>
#include <fcntl.h>  
#include <sys/stat.h> 
#include <sys/mman.h> 
#include <cstring>
#include <algorithm>
#include <limits.h>
#include <elf.h>

#include "Parser.hpp"
    
/**
 * @brief ELF-specific implementation of the abstract Parser interface.
 *
 * Parses ELF binary files and extracts sections, segments, symbols,
 * relocations, and function-related data.
 */
class ElfParser : public Parser {
public:
    /**
     * @brief Loads and parses the binary file at the given path.
     * 
     * 
     * @param path Path to the binary file to be loaded.
     */
    void load(const std::string& path) override;

    /**
     * @brief Returns parsed sections from the ELF file.
     * 
     * Really parses file only once than returns the cached result.
     * 
     * @return Reference to a vector of Section objects.
     */
    std::vector<Section>& get_sections() const override;

    /**
     * @brief Returns parsed segments from the ELF file.
     * 
     * Really parses file only once than returns the cached result.
     * 
     * @return Reference to a vector of Segment objects.
     */
    std::vector<Segment>& get_segments() const override;

    /**
     * @brief Returns parsed symbols from the ELF file.
     * 
     * Really parses file only once than returns the cached result.
     * 
     * @return Reference to a vector of Symbol objects.
     */
    std::vector<Symbol>& get_symbols() const override;

    /**
     * @brief Returns parsed relocations from the ELF file.
     * 
     * Really parses file only once than returns the cached result.
     * Also saves realocs_addrs_cache while parsing the first time.
     * 
     * @return Reference to a vector of Relocation objects.
     */
    std::vector<Relocation>& get_relocations() const override;

    /**
     * @brief Returns parsed function symbols from the ELF file.
     * 
     * Really parses file only once than returns the cached result.
     * The function is defined as a symbol of type function of non-zero size and without relocation entries.
     * 
     * @return Reference to a vector of Relocation objects.
     */
    std::vector<Symbol>& get_functions() const override;

    /**
     * @brief Gets the virtual address of the given function symbol.
     * @param func The function symbol to query.
     * @return Virtual address (VMA) of the function.
     * @warning PIE fies don't store the real virtual addresses. Therefore for them this function returns file offsets instead
     */
    uint64_t get_function_vaddr(Symbol func) const override;

    /**
     * @brief Returns a pointer to the function's memory inside the mapped binary.
     * @param func The function symbol.
     * @return Pointer to the beginning of the function in memory or nullptr on failure.
     */
    uint8_t* get_function_ptr(const Symbol &func) const override;

    /**
     * @brief Returns a currently unused virtual address (e.g., for code injection).
     * 
     * It searches the loadable segment with the greatest ending vaddr and returns the next page aligned address 
     * 
     * @return A vacant virtual memory address.
     */
    uint64_t get_vacant_vaddr() const override;

    /**
     * @brief Returns the starting virtual address of the code section.
     * 
     * The first loadable section with RE flags gives this address.
     * 
     * @return VMA of the code start (e.g., .text section).
     * @warning PIE fies don't store the real virtual addresses. Therefore for them this function returns file offsets instead
     */
    uint64_t get_code_start_vaddr() const override;

private:
    /**
     * @brief Returns human-readable name of section type.
     * @param type Raw ELF section type value.
     * @return String representation of the section type.
     */
    std::string get_section_type(int type) const;

    /**
     * @brief Returns human-readable name of segment type.
     * @param type Segment type field from `Elf_Phdr`.
     * @return String representation of the segment type.
     */
    std::string get_segment_type(uint32_t &type) const;

    /**
     * @brief Converts segment flags (PF_X, PF_R, PF_W) into a string like "RWE".
     * @param sflags Flags field from `Elf_Phdr`.
     * @return Human-readable flag string.
     */
    std::string get_segment_flags(uint32_t &sflags) const;

    /**
     * @brief Converts symbol type enum into a readable string.
     * @param type Raw symbol type value (from st_info).
     * @return String name of the symbol type (e.g. FUNC, OBJECT).
     */
    std::string get_symbol_type(uint8_t &type) const;

    /**
     * @brief Converts symbol binding enum into a readable string.
     * @param bind Raw symbol binding value.
     * @return String name of the binding (e.g. GLOBAL, LOCAL).
     */
    std::string get_symbol_bind(uint8_t &bind) const;

    /**
     * @brief Converts symbol visibility into a readable string.
     * @param vis Raw symbol visibility value.
     * @return Human-readable visibility name.
     */
    std::string get_symbol_visibility(uint8_t &vis) const;

    /**
     * @brief Converts symbol section index to a string (e.g., "UND", "ABS", or numeric index).
     * @param ind Raw section index.
     * @return String representation of symbol section index.
     */
    std::string get_symbol_index(uint16_t &ind) const;

    /**
     * @brief Converts relocation type to a readable name (architecture-specific).
     * @param type Relocation type value.
     * @return String name of relocation type.
     */
    std::string get_relocation_type(uint64_t &type) const;

    /**
     * @brief Resolves symbol value by its index for a given relocation.
     * @param ind Symbol table index.
     * @param syms Symbol table reference.
     * @return Value (usually address) of the symbol.
     */
    std::intptr_t get_relocation_symbol_value(uint64_t &ind, std::vector<Symbol> &syms) const;

    /**
     * @brief Resolves symbol name by its index for a given relocation.
     * @param ind Symbol table index.
     * @param syms Symbol table reference.
     * @return Symbol name.
     */
    std::string get_relocation_symbol_name(uint64_t &ind, std::vector<Symbol> &syms) const;
};

