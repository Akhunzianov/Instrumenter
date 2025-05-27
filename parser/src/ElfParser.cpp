#include "ElfParser.hpp"

// DEBUG out
// #include <iomanip>
// void print_bytes(const void* ptr, size_t count, const std::string& label) {
//     const unsigned char* bytes = reinterpret_cast<const unsigned char*>(ptr);
//     std::cout << label << ": ";
//     for (size_t i = 0; i < count; ++i) {
//         std::cout << std::hex << std::setw(2) << std::setfill('0')
//                   << static_cast<int>(bytes[i]) << " ";
//     }
//     std::cout << std::dec << std::endl;
// }

std::vector<Section> ElfParser::get_sections() const {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr*)prog_mmap;
    Elf64_Shdr *shdr = (Elf64_Shdr*)(prog_mmap + ehdr->e_shoff);
    int shnum = ehdr->e_shnum;
    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = (char*)prog_mmap + sh_strtab->sh_offset;

    // DEBUG out
    // print_bytes(ehdr, 16, "EHDR (first 16 bytes)");
    // print_bytes(prog_mmap + 0x4330, 16, "SHDR[0] (first 16 bytes)");
    // std::cout << ehdr->e_shoff << std::endl;

    std::vector<Section> sections;
    for (int i = 0; i < shnum; i++) {
        // DEBUG out
        // std::cout << i << std::endl;

        Section section;
        section.addr = shdr[i].sh_addr;

        // DEBUG out
        // std::cout << section.addr << std::endl;

        section.offset = shdr[i].sh_offset;

        // DEBUG out
        // std::cout << section.offset << std::endl;

        section.size = shdr[i].sh_size;

        // DEBUG out
        // std::cout << section.size << std::endl;

        section.name = std::string(sh_strtab_p + shdr[i].sh_name);

        // DEBUG out
        // std::cout << section.name << std::endl;

        section.extra["index"] = std::to_string(i);

        // DEBUG out
        // std::cout << section.extra["index"] << std::endl;

        section.extra["entry_size"] = std::to_string(shdr[i].sh_entsize);

        // DEBUG out
        // std::cout << section.extra["entry_size"] << std::endl;

        section.extra["align"] = std::to_string(shdr[i].sh_addralign);

        // DEBUG out
        // std::cout << section.extra["align"] << std::endl;

        section.extra["type"] = get_section_type(shdr[i].sh_type);

        // DEBUG out
        // std::cout << section.extra["type"] << std::endl;
        
        sections.push_back(std::move(section));

    }

    return sections;
}

std::vector<Segment> ElfParser::get_segments() const {
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
    return segments;
}

std::vector<Symbol> ElfParser::get_symbols() const {
    std::vector<Section> sections = get_sections();
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
            if(section.extra["type"] == "SHT_SYMTAB")
                symbol.name = std::string(sh_strtab_p + syms_data[i].st_name);
            if(section.extra["type"] == "SHT_DYNSYM")
                symbol.name = std::string(sh_dynstr_p + syms_data[i].st_name);
            symbol.extra["num"] = std::to_string(i);
            symbol.extra["index"] = get_symbol_index(syms_data[i].st_shndx);
            symbol.extra["section"] = section.name;
            
            symbols.push_back(symbol);
        }
    }
    return symbols;
}

std::vector<Relocation> ElfParser::get_relocations() const {
    auto sections = get_sections();
    auto syms = get_symbols();
    int32_t entry_size = 0;
    int64_t vma_addr = 0;
    for (auto &section : sections) {
        if(section.name == ".plt") {
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
            relocation.extra["addr"] = std::to_string(vma_addr + (i + 1) * entry_size);
            relocation.extra["section_name"] = section.name;
            relocation.extra["symbol_val"] = std::to_string(get_relocation_symbol_value(relocations_data[i].r_info, syms));
            
            relocations.push_back(relocation);
        }
    }
    return relocations;
}

std::vector<Symbol> ElfParser::get_functions() const {
    std::vector<Symbol> symbols = get_symbols();
    std::vector<Symbol> functions;
    for (auto &s : symbols) {
        if ((s.value != 0) && (s.type == "FUNC") && (!s.name.empty()) && (s.size >= 5)) // TODO: count realocs > 0 case, think what to do with short functions
            functions.push_back(s);
    }

    return functions;
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

void ElfParser::add_section(const std::string &name, const uint8_t *data, size_t len, uint64_t vaddr, uint8_t flags) {
    Elf64_Ehdr *old_ehdr = (Elf64_Ehdr*)prog_mmap;
    Elf64_Phdr *old_phdr = (Elf64_Phdr*)(prog_mmap + old_ehdr->e_phoff);
    Elf64_Shdr *old_shdr = (Elf64_Shdr*)(prog_mmap + old_ehdr->e_shoff);

    int32_t old_shnum = old_ehdr->e_shnum;
    int32_t old_phnum = old_ehdr->e_phnum;

    size_t align = 0x1000;
    size_t pad = (align - (prog_size % align)) % align;
    size_t insert_at = prog_size + pad;
    size_t new_phnum = old_phnum + 1;
    size_t new_shnum = old_shnum + 1;
    size_t phdr_size = new_phnum * sizeof(Elf64_Phdr);
    size_t shdr_size = new_shnum * sizeof(Elf64_Shdr);
    size_t new_size  = insert_at + len + phdr_size + shdr_size;

    std::vector<uint8_t> buf(new_size, 0);
    memcpy(buf.data(), prog_mmap, prog_size);
    memset(buf.data() + prog_size, 0, pad);
    memcpy(buf.data() + insert_at, data, len);

    size_t new_phoff = insert_at + len;
    memcpy(buf.data() + new_phoff, old_phdr, old_phnum * sizeof(Elf64_Phdr));

    Elf64_Phdr new_ph = {};
    new_ph.p_type   = PT_LOAD;
    new_ph.p_offset = insert_at;
    new_ph.p_vaddr  = vaddr;
    new_ph.p_paddr  = vaddr;
    new_ph.p_filesz = len;
    new_ph.p_memsz  = len;
    new_ph.p_flags  = flags; // PF_R|PF_W|PF_X mask
    new_ph.p_align  = align;
    memcpy(buf.data() + new_phoff + old_phnum * sizeof(Elf64_Phdr), &new_ph, sizeof(new_ph));

    size_t new_shoff = new_phoff + phdr_size;
    memcpy(buf.data() + new_shoff, old_shdr, old_shnum * sizeof(Elf64_Shdr));

    Elf64_Shdr new_sh = {};
    new_sh.sh_name      = 0;
    new_sh.sh_type      = SHT_PROGBITS;
    new_sh.sh_flags     = SHF_ALLOC | ((flags & PF_X) ? SHF_EXECINSTR : 0) | ((flags & PF_W) ? SHF_WRITE : 0);
    new_sh.sh_addr      = vaddr;
    new_sh.sh_offset    = insert_at;
    new_sh.sh_size      = len;
    new_sh.sh_addralign = align;
    memcpy(buf.data() + new_shoff + old_shnum * sizeof(Elf64_Shdr), &new_sh, sizeof(new_sh));

    Elf64_Ehdr new_ehdr = *old_ehdr;
    new_ehdr.e_phoff = new_phoff;
    new_ehdr.e_shoff = new_shoff;
    new_ehdr.e_phnum = new_phnum;
    new_ehdr.e_shnum = new_shnum;
    memcpy(buf.data(), &new_ehdr, sizeof(new_ehdr));

    int fd_out = open(out_prog_path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0755);
    if (fd_out < 0) {
        perror("add_section: open output");
        return;
    }
    ssize_t written = write(fd_out, buf.data(), new_size);
    if (written < 0 || static_cast<size_t>(written) != new_size) {
        perror("add_section: write output");
        close(fd_out);
        return;
    }
    if (close(fd_out) < 0) {
        perror("add_section: close output");
        return;
    }
    if (munmap(prog_mmap, prog_size) < 0) {
        perror("add_section: munmap old");
    }
    struct stat st;
    int fd_new = open(out_prog_path.c_str(), O_RDONLY);
    if (fd_new < 0) {
        perror("add_section: open new");
        return;
    }
    if (fstat(fd_new, &st) < 0) {
        perror("add_section: fstat new");
        close(fd_new);
        return;
    }
    prog_size = st.st_size;
    uint8_t *new_map = static_cast<uint8_t*>(mmap(nullptr, prog_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd_new, 0));
    if (new_map == MAP_FAILED) {
        perror("add_section: mmap new");
        close(fd_new);
        return;
    }
    prog_mmap = new_map;

    // DEBUG out
    // std::cout << "prgsize "<< prog_size << std::endl;

    if (close(fd_new) < 0) {
        perror("add_section: close new");
    }
}

void ElfParser::sync_map_file() {
    int fd_out = open(out_prog_path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0755);
    if (fd_out < 0) {
        perror("sync_map_file: open output");
        return;
    }
    ssize_t written = write(fd_out, prog_mmap, prog_size);
    if (written < 0 || static_cast<size_t>(written) != prog_size) {
        perror("add_section: write output");
        close(fd_out);
        return;
    }
    if (close(fd_out) < 0) {
        perror("sync_map_file: close output");
        return;
    }
}


void ElfParser::load(const std::string& path, const std::string& out_path) {
    fileType = ELF;
    prog_path = path; 
    out_prog_path = out_path;
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
}

