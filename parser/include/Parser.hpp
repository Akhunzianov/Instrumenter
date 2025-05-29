#pragma once

#include <vector>
#include <string>

#include "types.hpp"

/**
 * @brief Supported binary file formats.
 */
enum FileTypes { 
    ELF 
};

/**
 * @brief Supported architecture types.
 */
enum ArchTypes { 
    X86_64 // x86_64 architecture (64-bit Intel/AMD)
};

/**
 * @brief Abstract interface for binary file parsers.
 *
 * The Parser class provides a uniform interface for parsing binary executable
 * files (e.g., ELF, Mach-O, PE, ...) and accessing their sections, segments, symbols, 
 * relocations, and function-related information.
 */
class Parser {
public:
    FileTypes fileType;          // Type of the parsed file (e.g., ELF).
    ArchTypes archType = X86_64; // Architecture type (e.g., X86_64). To be determined during parsing.
    std::string prog_path;       // Absolute path to the parsed binary.
    size_t prog_size;            // Size of the binary file in bytes.
    uint8_t* prog_mmap;          // Pointer to memory-mapped binary contents.

    // Virtual destructor.
    virtual ~Parser() = default;

    /**
     * @brief Loads and parses the binary file at the given path.
     * 
     * During execution performs a private map of bin file in its address space.
     * On failure the error message will be printed and exit will occur
     * 
     * @param path Path to the binary file to be loaded.
     */
    virtual void load(const std::string& path) = 0;

    /**
     * @brief Returns a reference to the list of parsed sections.
     * 
     * And saves it in the sections_cache field
     * 
     * @return Vector of Section objects.
     */
    virtual std::vector<Section>& get_sections() const = 0;

    /**
     * @brief Returns a reference to the list of parsed segments.
     * 
     * And saves it in the segments_cache field
     * 
     * @return Vector of Segment objects.
     */
    virtual std::vector<Segment>& get_segments() const = 0;

    /**
     * @brief Returns a reference to the list of parsed segments.
     * 
     * And saves it in the segments_cache field
     * 
     * @return Vector of Segment objects.
     */
    virtual std::vector<Symbol>& get_symbols() const = 0;

    /**
     * @brief Returns a reference to the list of parsed relocations.
     * 
     * And saves it in the relocations_cache field
     * 
     * @return Vector of Relocation objects.
     */
    virtual std::vector<Relocation>& get_relocations() const = 0;

    /**
     * @brief Returns a reference to the list of parsed functions (symbols of function type).
     * 
     * And saves it in the relocations_cache field
     * 
     * @return Vector of Symbol objects.
     */
    virtual std::vector<Symbol>& get_functions() const = 0;

    /**
     * @brief Gets the virtual address of the given function symbol.
     * @param func The function symbol to query.
     * @return Virtual address (VMA) of the function.
     * @warning PIE fies don't store the real virtual addresses. Therefore for them this function returns file offsets instead
     */
    virtual uint64_t get_function_vaddr(Symbol func) const = 0;

    /**
     * @brief Returns a pointer to the function's memory inside the mapped binary.
     * @param func The function symbol.
     * @return Pointer to the beginning of the function in memory.
     */
    virtual uint8_t* get_function_ptr(const Symbol &func) const = 0;

    /**
     * @brief Returns a currently unused virtual address (e.g., for code injection).
     * 
     * It searches the loadable segment with the greatest ending vaddr and returns the next page aligned address 
     * 
     * @return A vacant virtual memory address.
     */
    virtual uint64_t get_vacant_vaddr() const = 0;

    /**
     * @brief Returns the starting virtual address of the code section.
     * 
     * The first loadable section with RE flags gives this address.
     * 
     * @return VMA of the code start (e.g., .text section).
     * @warning PIE fies don't store the real virtual addresses. Therefore for them this function returns file offsets instead
     */
    virtual uint64_t get_code_start_vaddr() const = 0;

private:
    /**
     * @brief Cached list of parsed sections.
     *
     * Populated on first call to get_sections(). Marked mutable to allow lazy evaluation in const context.
     */
    mutable std::vector<Section> sections_cache;

    /**
     * @brief Cached list of program segments.
     *
     * Populated on first call to get_segments(). Marked mutable to allow lazy evaluation in const context.
     */
    mutable std::vector<Segment> segments_cache;

    /**
     * @brief Cached list of parsed symbols.
     *
     * Populated on first call to get_symbols(). Marked mutable to allow lazy evaluation in const context.
     */
    mutable std::vector<Symbol> symbols_cache;

    /**
     * @brief Cached list of relocation entries.
     *
     * Populated on first call to get_realocations(). Marked mutable to allow lazy evaluation in const context.
     */
    mutable std::vector<Relocation> realocations_cache;

    /**
     * @brief Cached list of function symbols.
     *
     * Extracted from the general symbol table on first call to get_functions().
     */
    mutable std::vector<Symbol> functions_cache;

    /**
     * @brief Cached list of addresses where relocations apply.
     *
     * Helps optimize relocation lookup and instrumentation logic.
     */
    mutable std::vector<uint64_t> realocs_addrs_cache;
};

/**
 * @brief Factory function to create an appropriate parser instance for a given file.
 * 
 * Determines the file format and architecture and returns a suitable Parser subclass instance.
 *
 * @param path Path to the binary file.
 * @return Unique pointer to the created Parser instance.
 */
std::unique_ptr<Parser> createParser(const std::string& path);
