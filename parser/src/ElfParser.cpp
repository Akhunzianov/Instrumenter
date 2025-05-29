#include "ElfParser.hpp"

std::vector<Section>& ElfParser::get_sections() const {
    if (sections_cache.size())
        return sections_cache;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)prog_mmap;
    Elf64_Shdr *shdr = (Elf64_Shdr*)(prog_mmap + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;
    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = (char*)prog_mmap + sh_strtab->sh_offset;

    std::vector<Section> sections;
    for (int i = 0; i < shnum; i++) {
        Section section;
        section.addr = shdr[i].sh_addr;
        section.offset = shdr[i].sh_offset;
        section.size = shdr[i].sh_size;
        section.name = std::string(sh_strtab_p + shdr[i].sh_name);
        section.extra["index"] = std::to_string(i);
        section.extra["entry_size"] = std::to_string(shdr[i].sh_entsize);
        section.extra["align"] = std::to_string(shdr[i].sh_addralign);
        section.extra["type"] = get_section_type(shdr[i].sh_type);
        sections.push_back(std::move(section));
    }
    sections_cache = sections;
    return sections_cache;
}

std::vector<Segment>& ElfParser::get_segments() const {
    if (segments_cache.size())
        return segments_cache;
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)prog_mmap;
    Elf64_Phdr *phdr = (Elf64_Phdr*)(prog_mmap + ehdr->e_phoff);
    int phnum = ehdr->e_phnum;
    Elf64_Shdr *shdr = (Elf64_Shdr*)(prog_mmap + ehdr->e_shoff);
    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = (char*)prog_mmap + sh_strtab->sh_offset;

    std::vector<Segment> segments;
    for (int i = 0; i < phnum; ++i) {
        Segment segment;
        segment.type = get_segment_type(phdr[i].p_type);
        segment.offset = phdr[i].p_offset;
        segment.vma = phdr[i].p_vaddr;
        segment.lma = phdr[i].p_paddr;
        segment.filesize = phdr[i].p_filesz;
        segment.memsize = phdr[i].p_memsz;
        segment.flags = get_segment_flags(phdr[i].p_flags);
        segment.extra["align"] = std::to_string(phdr[i].p_align);
        segments.push_back(segment);
    }
    segments_cache = segments;
    return segments_cache;
}

std::vector<Symbol>& ElfParser::get_symbols() const {
    if (symbols_cache.size())
        return symbols_cache;
    std::vector<Section>& sections = get_sections();
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)prog_mmap;
    Elf64_Shdr *shdr = (Elf64_Shdr*)(prog_mmap + ehdr->e_shoff);
    char *sh_strtab_p = nullptr;
    for (auto &section: sections) {
        if ((section.extra["type"] == "SHT_STRTAB") && (section.name == ".strtab")) {
            sh_strtab_p = (char*)prog_mmap + section.offset;
            break;
        }
    }
    char *sh_dynstr_p = nullptr;
    for (auto &section: sections) {
        if ((section.extra["type"] == "SHT_STRTAB") && (section.name == ".dynstr")) {
            sh_dynstr_p = (char*)prog_mmap + section.offset;
            break;
        }
    }

    std::vector<Symbol> symbols;
    for (auto &section: sections) {
        if ((section.extra["type"] != "SHT_SYMTAB") && (section.extra["type"] != "SHT_DYNSYM"))
            continue;
        auto total_syms = section.size / sizeof(Elf64_Sym);
        auto syms_data = (Elf64_Sym*)(prog_mmap + section.offset);
        for (int i = 0; i < total_syms; ++i) {
            Symbol symbol;
            symbol.value = syms_data[i].st_value;
            symbol.size = syms_data[i].st_size;
            symbol.type = get_symbol_type(syms_data[i].st_info);
            symbol.bind = get_symbol_bind(syms_data[i].st_info);
            symbol.visibility = get_symbol_visibility(syms_data[i].st_other);
            if (section.extra["type"] == "SHT_SYMTAB")
                symbol.name = std::string(sh_strtab_p + syms_data[i].st_name);
            if (section.extra["type"] == "SHT_DYNSYM")
                symbol.name = std::string(sh_dynstr_p + syms_data[i].st_name);
            symbol.extra["num"] = std::to_string(i);
            symbol.extra["index"] = get_symbol_index(syms_data[i].st_shndx);
            symbol.extra["section"] = section.name;
            
            symbols.push_back(symbol);
        }
    }
    symbols_cache = symbols;
    return symbols_cache;
}

std::vector<Relocation>& ElfParser::get_relocations() const {
    if (realocations_cache.size())
        return realocations_cache;
    auto sections = get_sections();
    auto syms = get_symbols();
    int32_t entry_size = 0;
    uint64_t vma_addr = 0;
    for (auto &section : sections) {
        if (section.name == ".plt") {
          entry_size = std::stoi(section.extra["entry_size"]);
          vma_addr = section.addr;
          break;
        }
    }
    std::vector<Relocation> relocations;
    for (auto &section : sections) {
        if (section.extra["type"] != "SHT_RELA") 
            continue;
        auto total_relocations = section.size / sizeof(Elf64_Rela);
        auto relocations_data  = (Elf64_Rela*)(prog_mmap + section.offset);
        for (int i = 0; i < total_relocations; ++i) {
            Relocation relocation;
            relocation.offset = static_cast<std::intptr_t>(relocations_data[i].r_offset);
            relocation.info = static_cast<std::intptr_t>(relocations_data[i].r_info);
            relocation.type = get_relocation_type(relocations_data[i].r_info);
            relocation.symbol_name = get_relocation_symbol_name(relocations_data[i].r_info, syms);
            relocation.addr = vma_addr + (i + 1) * entry_size;
            realocs_addrs_cache.push_back(vma_addr + (i + 1) * entry_size);
            relocation.extra["section_name"] = section.name;
            relocation.extra["symbol_val"] = std::to_string(get_relocation_symbol_value(relocations_data[i].r_info, syms));
            
            relocations.push_back(relocation);
        }
    }
    realocations_cache = relocations;
    return realocations_cache;
}

std::vector<Symbol>& ElfParser::get_functions() const {
    if (functions_cache.size())
        return functions_cache;
    std::vector<Symbol> symbols = get_symbols();
    std::vector<Symbol> functions;
    for (auto &s : symbols) {
        if ((s.value != 0) && (s.type == "FUNC") && (!s.name.empty()) && !std::count(realocs_addrs_cache.begin(), realocs_addrs_cache.end(), s.value))
            functions.push_back(s);
    }
    functions_cache = functions;
    return functions_cache;
}



uint64_t ElfParser::get_function_vaddr(Symbol func) const {
    uint64_t func_vaddr = func.value;
    return func_vaddr;
}

uint8_t* ElfParser::get_function_ptr(const Symbol &func) const {
    for (auto &sec : get_sections()) {
        uint64_t vstart = sec.addr;
        uint64_t vend = sec.addr + sec.size;
        if (func.value >= vstart && func.value < vend) {
            uint64_t file_off = sec.offset + (func.value - vstart);
            return prog_mmap + file_off;
        }
    }
    return nullptr;
}

uint64_t ElfParser::get_vacant_vaddr() const {
    Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr*>(prog_mmap);
    Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr*>(prog_mmap + ehdr->e_phoff);
    size_t page_sz = getpagesize();
    uint64_t max_end = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type != PT_LOAD) 
            continue;
        uint64_t end = phdr[i].p_vaddr + phdr[i].p_memsz;
        if (end > max_end) 
            max_end = end;
    }
    uint64_t code_base = (max_end + page_sz - 1) & ~(page_sz - 1);
    return code_base;
}

uint64_t ElfParser::get_code_start_vaddr() const {
    uint64_t min_start = INT64_MAX;
    for (auto &seg : get_segments()) {
        uint64_t vstart = seg.vma;
        if (vstart < min_start && seg.flags == "RE")
	    min_start = vstart;
    }
    return min_start;
}

std::string ElfParser::get_section_type(int type) const {
    if (type < 0) return "UNKNOWN";
    switch (type) {
        case 0: return "SHT_NULL";    
        case 1: return "SHT_PROGBITS";
        case 2: return "SHT_SYMTAB";   
        case 3: return "SHT_STRTAB"; 
        case 4: return "SHT_RELA"; 
        case 5: return "SHT_HASH";  
        case 6: return "SHT_DYNAMIC";
        case 7: return "SHT_NOTE";     
        case 8: return "SHT_NOBITS";    
        case 9: return "SHT_REL";    
        case 11: return "SHT_DYNSYM"; 
        default: return "UNKNOWN";
    }

    return "UNKNOWN";
}

std::string ElfParser::get_segment_type(uint32_t &type) const {
    switch (type) {
        case PT_NULL:   return "NULL";               
        case PT_LOAD: return "LOAD";         
        case PT_DYNAMIC: return "DYNAMIC";        
        case PT_INTERP: return "INTERP";     
        case PT_NOTE: return "NOTE";                  
        case PT_SHLIB: return "SHLIB";               
        case PT_PHDR: return "PHDR";                   
        case PT_TLS: return "TLS";                 
        case PT_NUM: return "NUM";            
        case PT_LOOS: return "LOOS";               
        case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case PT_GNU_STACK: return "GNU_STACK";     
        case PT_GNU_RELRO: return "GNU_RELRO";   
        //case PT_LOSUNW: return "LOSUNW";
        case PT_SUNWBSS: return "SUNWBSS";       
        case PT_SUNWSTACK: return "SUNWSTACK";       
        //case PT_HISUNW: return "HISUNW";
        case PT_HIOS: return "HIOS";              
        case PT_LOPROC: return "LOPROC";      
        case PT_HIPROC: return "HIPROC";       
        default: return "UNKNOWN";
    }
}

std::string ElfParser::get_segment_flags(uint32_t &sflags) const {
    std::string flags;
    if (sflags & PF_R)
        flags.append("R");
    if (sflags & PF_W)
        flags.append("W");
    if (sflags & PF_X)
        flags.append("E");
    return flags;
}

std::string ElfParser::get_symbol_type(uint8_t &type) const {
    switch (ELF32_ST_TYPE(type)) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 6: return "TLS";
        case 7: return "NUM";
        case 10: return "LOOS";
        case 12: return "HIOS";
        default: return "UNKNOWN";
    }
}

std::string ElfParser::get_symbol_bind(uint8_t &bind) const {
    switch (ELF32_ST_BIND(bind)) {
        case 0: return "LOCAL";
        case 1: return "GLOBAL";
        case 2: return "WEAK";
        case 3: return "NUM";
        case 10: return "UNIQUE";
        case 12: return "HIOS";
        case 13: return "LOPROC";
        default: return "UNKNOWN";
    }
}

std::string ElfParser::get_symbol_visibility(uint8_t &vis) const {
    switch (ELF32_ST_VISIBILITY(vis)) {
        case 0: return "DEFAULT";
        case 1: return "INTERNAL";
        case 2: return "HIDDEN";
        case 3: return "PROTECTED";
        default: return "UNKNOWN";
    }
}

std::string ElfParser::get_symbol_index(uint16_t &ind) const {
    switch (ind) {
        case SHN_ABS: return "ABS";
        case SHN_COMMON: return "COM";
        case SHN_UNDEF: return "UND";
        case SHN_XINDEX: return "COM";
        default: return std::to_string(ind);
    }
}

std::string ElfParser::get_relocation_type(uint64_t &type) const {
    switch (ELF64_R_TYPE(type)) {
        case 1: return "R_X86_64_32";
        case 2: return "R_X86_64_PC32";
        case 5: return "R_X86_64_COPY";
        case 6: return "R_X86_64_GLOB_DAT";
        case 7:  return "R_X86_64_JUMP_SLOT";
        default: return "OTHERS";
    }
}

std::intptr_t ElfParser::get_relocation_symbol_value(uint64_t &ind, std::vector<Symbol> &syms) const {
    std::intptr_t sym_val = 0;
    for (auto &sym: syms) {
        if (std::stol(sym.extra["num"]) == ELF64_R_SYM(ind)) {
            sym_val = sym.value;
            break;
        }
    }
    return sym_val;
}

std::string ElfParser::get_relocation_symbol_name(uint64_t &ind, std::vector<Symbol> &syms) const {
    std::string sym_name;
    for (auto &sym: syms) {
        if (std::stol(sym.extra["num"]) == ELF64_R_SYM(ind)) {
            sym_name = sym.name;
            break;
        }
    }
    return sym_name;
}

void ElfParser::load(const std::string& path) {
    fileType = ELF;
    char abs_path_buf[PATH_MAX];
    if (realpath(path.c_str(), abs_path_buf) == nullptr) {
        perror("realpath");
        exit(-1);
    }
    prog_path = std::string(abs_path_buf);
    int fd, i;
    struct stat st;
    if ((fd = open(prog_path.c_str(), O_RDONLY)) < 0) {
        printf("Err: open\n");
        exit(-1);
    }
    if (fstat(fd, &st) < 0) {
        printf("Err: fstat\n");
        exit(-1);
    }
    prog_size = st.st_size;
    prog_mmap = static_cast<uint8_t*>(mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0));
    if (prog_mmap == MAP_FAILED) {
        printf("Err: mmap\n");
        exit(-1);
    }

    Elf64_Ehdr * header = (Elf64_Ehdr*)prog_mmap;
    if (header->e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Only 64-bit files supported\n");
        exit(1);
    }
    switch (header->e_machine) {
    case EM_X86_64:
        archType = X86_64;
        break;
    default:
        printf("Unsupported architecture (e_machine = %d)\n", header->e_machine);
        exit(1);
    }
    get_sections();
    get_segments();
    get_symbols();
    get_relocations();
    get_functions();
}


