#pragma once

#include <string>
#include <cstdio>
#include <map>
#include <memory>

/** @struct foreignstruct
 *  @brief Represents a section in a binary file (e.g., ELF).
 *  
 *  
 *  
 * 
 */
struct Section {
    std::string name;     // Name of the section (e.g. ".text", ".data").
    std::intptr_t offset; // Offset from the beginning of the file.
    std::intptr_t addr;   // Virtual address where the section is loaded (for PIEs offset).            
    int32_t size;         // Size of the section in bytes.
    std::map<std::string, std::string> extra; // Additional metadata (e.g. type, flags) (format dependent).
};

/** @struct foreignstruct
 *  @brief Represents a program segment (PT_LOAD, PT_DYNAMIC, etc.).
 *  
 *  Segments are ranges of memory loaded into the process at runtime.
 *  Used for memory layout and permissions.
 * 
 */
struct Segment {
    std::string type;   // Segment type (e.g. "LOAD", "DYNAMIC", etc.).
    std::string flags;  // Access flags (e.g. "R", "RWX").
    int64_t offset;     // Offset in the file where segment data starts.
    int64_t vma;        // Virtual memory address where segment is mapped (for PIEs offset).
    int64_t lma;        // Physical memory address (often same as VMA).
    int64_t filesize;   // Size of the segment in the file.
    int64_t memsize;    // Size of the segment in memory (may include BSS).
    std::map<std::string, std::string> extra; // Additional segment attributes (format dependent).
};

/** @struct foreignstruct
 *  @brief Represents a symbol (variable, function, etc.) from the symbol table.
 *  
 *  Contains identifying metadata and binding information.
 *  
 * 
 */
struct Symbol {
    std::string name;       // Name of the symbol (e.g. "main", "printf").
    std::string bind;       // Symbol binding (e.g. "LOCAL", "GLOBAL").
    std::string visibility; // Symbol visibility (e.g. "DEFAULT", "HIDDEN").
    std::string type;       // Symbol type (e.g. "FUNC", "OBJECT").
    std::intptr_t value;    // Address or value of the symbol.
    int32_t size = 0;       // Size of the symbol (used for functions/objects).
    std::map<std::string, std::string> extra; // Additional attributes (format dependent).
};

/** @struct foreignstruct
 *  @brief Represents a relocation entry (patchable address that references a symbol).
 *  
 *  Used to adjust symbol references at load time or link time.
 *  
 * 
 */
struct Relocation {
    std::intptr_t offset;     // Location in code or data where relocation applies.
    std::intptr_t info;       // Encoded info about relocation type and symbol.
    std::string type;         // Human-readable relocation type (e.g. "R_X86_64_PC32").
    std::string symbol_name;  // Name of the associated symbol.
    uint64_t addr;            // Resolved address (if available).
    std::map<std::string, std::string> extra; // Extra relocation metadata.
};
