#include "Instrument.hpp"

#define SECTION_R_FLAG (1 << 2)
#define SECTION_W_FLAG (1 << 1)
#define SECTION_X_FLAG (1 << 0)

// extern "C" void __instrument_event(uint32_t);

// size_t Instrument::get_prologue_size(uint8_t* code, size_t max_len) {
//     auto [arch, mode] = get_capstone_config(real_parser->archType);
//     size_t min_size = get_min_prolog_size(real_parser->archType);
    
//     csh handle;
//     if (cs_open(arch, mode, &handle) != CS_ERR_OK)
//         throw std::runtime_error("Capstone initialization failed");
    
//     size_t offset = 0;
//     while (offset < min_size) {
//         cs_insn* insn;
//         size_t count = cs_disasm(handle, code + offset, max_len - offset, 0, 1, &insn); // TODO: add reletive address handaling
//         if (count == 0) {
//             cs_close(&handle);
//             throw std::runtime_error("Disasm failed");
//         }
//         offset += insn[0].size;
//         cs_free(insn, count);
//     }
    
//     cs_close(&handle);
//     return offset;
// }

std::vector<uint8_t> Instrument::make_back_trampoline(uint32_t func_id, uint64_t handler_addr, uint64_t tramp_addr, uint64_t ret_addr) {
    auto [arch, mode] = get_keystone_config(real_parser->archType);

    ks_engine* ks;
    if (ks_open(arch, mode, &ks) != KS_ERR_OK)
        throw std::runtime_error("Keystone initialization failed");

    char asm_tmpl[1024];
    std::snprintf(asm_tmpl, sizeof(asm_tmpl),
        get_asm_back_trampoline(real_parser->archType),
        func_id,
        static_cast<unsigned long long>(handler_addr),
        static_cast<unsigned long long>(ret_addr)
    );

    unsigned char* enc;
    size_t encsz, cnt;
    size_t err = ks_asm(ks, asm_tmpl, tramp_addr, &enc, &encsz, &cnt);
    
    // DEBUG out
    // std::cout << "asm_tmpl: " << asm_tmpl << std::endl;

    if (err != KS_ERR_OK) {
        std::string msg = ks_strerror(ks_errno(ks));
        ks_close(ks);
        throw std::runtime_error(msg);
    }

    std::vector<uint8_t> code(enc, enc + encsz);
    ks_free(enc); 
    ks_close(ks);
    return code;
}

std::vector<uint8_t> Instrument::make_front_trampoline(uint32_t func_id, uint64_t handler_addr, uint64_t tramp_addr, uint64_t ret_addr) {
    auto [arch, mode] = get_keystone_config(real_parser->archType);

    ks_engine* ks;
    if (ks_open(arch, mode, &ks) != KS_ERR_OK)
        throw std::runtime_error("Keystone initialization failed");

    char asm_tmpl[1024];
    std::snprintf(asm_tmpl, sizeof(asm_tmpl),
        get_asm_front_trampoline(real_parser->archType)
    );

    unsigned char* enc;
    size_t encsz, cnt;
    size_t err = ks_asm(ks, asm_tmpl, tramp_addr, &enc, &encsz, &cnt);
    
    // DEBUG out
    // std::cout << "asm_tmpl: " << asm_tmpl << std::endl;

    if (err != KS_ERR_OK) {
        std::string msg = ks_strerror(ks_errno(ks));
        ks_close(ks);
        throw std::runtime_error(msg);
    }

    std::vector<uint8_t> code(enc, enc + encsz);
    ks_free(enc); 
    ks_close(ks);
    return code;
}

std::pair<std::vector<uint8_t>, size_t> Instrument::rewrite_prolog(uint8_t* func_ptr, uint8_t* tramp_addr) {
    auto [arch, mode] = get_keystone_config(real_parser->archType);

    ks_engine* ks;
    if (ks_open(arch, mode, &ks) != KS_ERR_OK)
        throw std::runtime_error("Keystone initialization failed");

    char asm_tmpl[512];
    std::snprintf(asm_tmpl, sizeof(asm_tmpl),
        get_asm_prologue(real_parser->archType),
        static_cast<unsigned long long>(reinterpret_cast<uint64_t>(tramp_addr))
    );

    unsigned char* enc;
    size_t encsz, cnt;

    if (ks_asm(ks, asm_tmpl, 0, &enc, &encsz, &cnt) != KS_ERR_OK) {
        std::string msg = ks_strerror(ks_errno(ks));
        ks_close(ks);
        throw std::runtime_error(msg);
    }

    std::vector<uint8_t> code(enc, enc + encsz);
    ks_free(enc); 
    ks_close(ks);
    
    // TODO: add check for backwards jumps via absolute addresses
    auto [arch1, mode1] = get_capstone_config(real_parser->archType);
    size_t min_size = encsz;

    csh handle;
    if (cs_open(arch1, mode1, &handle) != CS_ERR_OK)
        throw std::runtime_error("Capstone initialization failed");
    
    size_t offset = 0;
    while (offset < min_size) {
        cs_insn* insn;
        size_t count = cs_disasm(                               // TODO: add absolute address handaling
            handle, func_ptr + offset, 
            reinterpret_cast<uint64_t>(func_ptr + offset), 
            0, 1, &insn
        );                              
        if (count == 0) {
            cs_close(&handle);
            throw std::runtime_error("Disasm failed");
        }
        offset += insn[0].size;
        cs_free(insn, count);
    }
    cs_close(&handle);

    std::vector<uint8_t> func_start(func_ptr, func_ptr + offset);

    std::memcpy(func_ptr, code.data(), code.size());
    for (size_t i = 0; i < offset - code.size(); ++i)
        func_ptr[i] = 0x90;      // TODO: make fill with nop arch independent
    
    return { func_start, offset };
}

// DEBUG out
void print_bytes(uint8_t* ptr, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(ptr[i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << "\n";
    }
    std::cout << std::dec << std::endl; 
}

void Instrument::allocate_data_section(uint64_t base_vaddr) {
    size_t counters_len = functions.size() * sizeof(uint64_t);
    std::vector<uint8_t> zero_buf(counters_len, 0);
    real_parser->add_section(".counters", zero_buf.data(), counters_len, base_vaddr, SECTION_R_FLAG | SECTION_W_FLAG);
}

std::vector<uint8_t> Instrument::make_event_handler(uint64_t data_base, int32_t threshold, int32_t out_fd) {
    auto [arch, mode] = get_keystone_config(real_parser->archType);

    ks_engine* ks;
    if (ks_open(arch, mode, &ks) != KS_ERR_OK)
        throw std::runtime_error("Keystone initialization failed");

    char asm_tmpl[4096];
    std::snprintf(asm_tmpl, sizeof(asm_tmpl),
        get_asm_event(real_parser->archType),
        static_cast<unsigned long long>(data_base),
        static_cast<unsigned int>(threshold),
        static_cast<int>(out_fd)
    );

    unsigned char* enc;
    size_t encsz, cnt;

    if (ks_asm(ks, asm_tmpl, 0, &enc, &encsz, &cnt) != KS_ERR_OK) {
        std::string msg = ks_strerror(ks_errno(ks));
        ks_close(ks);
        throw std::runtime_error(msg);
    }

    std::vector<uint8_t> code(enc, enc + encsz);
    ks_free(enc); 
    ks_close(ks);
    return code;
}

void Instrument::instrument_functions() {
    functions = real_parser->get_functions();
    if (functions.empty()) 
        return;

    uint64_t code_base = real_parser->get_vacant_vaddr();
    allocate_data_section(code_base);

    size_t page_sz = getpagesize();
    size_t counters_len = functions.size() * sizeof(uint64_t);
    uint64_t code_section_addr = ((code_base + counters_len + page_sz - 1) & ~(page_sz - 1));

    constexpr size_t SLAB_SIZE = 64 * 1024;
    uint8_t* slab = reinterpret_cast<uint8_t*>(mmap(nullptr, SLAB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (slab == MAP_FAILED) 
        throw std::runtime_error("instrument_functios: mmap slab failed");
    size_t slab_off = 0;

    auto event_handler_bytes = make_event_handler(code_base, 5, 3); // TODO: get rid of magic consts 
    std::memcpy(slab, event_handler_bytes.data(), event_handler_bytes.size());
    slab_off += event_handler_bytes.size();

    // DEBUG out
    std::cout << "123" << std::endl;

    for (uint32_t id = 0; id < functions.size(); ++id) {
        const Symbol &func = functions[id];
        uint8_t* func_ptr = real_parser->get_function_ptr(func);
        if (!func_ptr) 
            continue;

        // DEBUG out
        std::cout << "\nid: " << id << " name: " << func.name << std::endl;

        // DEBUG out
        // std::cout << "prolog size: " << prologue_size << " ptr: " << (uint64_t)func_ptr << " vaddr: " << (uint64_t)func.value << " prog_mmap: " << (uint64_t)prog_mmap << std::endl;
        std::cout << std::hex << " ptr: " << (uint64_t)func_ptr << " vaddr: " << (uint64_t)func.value << " prog_mmap: " << (uint64_t)real_parser->prog_mmap << std::endl;
        std::cout << "orig bytes: ";
        print_bytes(func_ptr, 10);
        // std::cout << "orig bytes: ";
        // print_bytes(func_ptr, 10);

        uint8_t* tramp = slab + slab_off;

        std::pair<std::vector<uint8_t>, size_t> prologue_rewrite_res = rewrite_prolog(func_ptr, tramp);
        std::vector<uint8_t> func_start = prologue_rewrite_res.first;
        size_t prologue_size = prologue_rewrite_res.second;

        auto tbytes = make_front_trampoline(
            id,                     
            code_base,   
            reinterpret_cast<uint64_t>(tramp),          
            reinterpret_cast<uint64_t>(func_ptr + prologue_size)
        );
        memcpy(tramp, tbytes.data(), tbytes.size());
        slab_off += tbytes.size();
        tramp = slab + slab_off;

        memcpy(tramp, func_start.data(), func_start.size());
        slab_off += func_start.size();
        tramp = slab + slab_off;

        tbytes = make_back_trampoline(
            id,                     
            code_base,   
            reinterpret_cast<uint64_t>(tramp),          
            reinterpret_cast<uint64_t>(func_ptr + prologue_size)
        );
        memcpy(tramp, tbytes.data(), tbytes.size());
        slab_off += tbytes.size();
    }

    real_parser->sync_map_file();
    real_parser->add_section(".instrument_code", slab, slab_off, code_section_addr, SECTION_R_FLAG | SECTION_X_FLAG);

    if (munmap(slab, slab_off) < 0) {
        perror("instrument_functios: munmap slab failed");
    }
}

// void Instrument::instrument_functions() {
//     functions = get_functions();
//     if (functions.empty()) 
//         return;

//     constexpr size_t SLAB_SIZE = 64 * 1024;
//     uint8_t* slab = reinterpret_cast<uint8_t*>(
//         mmap(nullptr, SLAB_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
//     if (slab == MAP_FAILED) 
//         throw std::runtime_error("mmap slab failed");
//     size_t slab_off = 0;

        
//     for (uint32_t id = 0; id < functions.size(); ++id) {
//         const Symbol& func = functions[id];

//         // DEBUG out
//         std::cout << "\nid: " << id << " name: " << func.name << std::endl;

//         uint8_t* func_ptr = get_function_ptr(func);
//         if (!func_ptr) 
//             continue;

//         size_t prologue_size = get_prologue_size(func_ptr, 15); // TODO: calculate max_len for each func

//         // DEBUG out
//         std::cout << "prolog size: " << prologue_size << " ptr: " << (uint64_t)func_ptr << " vaddr: " << (uint64_t)func.value << " prog_mmap: " << (uint64_t)prog_mmap << std::endl;
//         std::cout << "orig bytes: ";
//         print_bytes(func_ptr, 10);

//         uint8_t* tramp_addr = slab + slab_off;
//         std::memcpy(tramp_addr, func_ptr, prologue_size);
//         bool use_abs;
//         std::vector<uint8_t> tramp = make_trampoline(id,
//             reinterpret_cast<uint64_t>(&__instrument_event),
//             reinterpret_cast<uint64_t>(tramp_addr),
//             reinterpret_cast<uint64_t>(func_ptr + prologue_size),
//             use_abs
//         );

//         std::memcpy(tramp_addr, tramp.data(), tramp.size());
//         slab_off += tramp.size();

//         void* page = reinterpret_cast<void*>((uintptr_t)func_ptr & ~(getpagesize()-1));
//         mprotect(page, getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC);

//         rewrite_prolog(func_ptr, tramp_addr, prologue_size, use_abs);

//         mprotect(page, getpagesize(), PROT_READ | PROT_EXEC);

//         // DEBUG out
//         std::cout << "tramp ptr: " << (uint64_t)tramp_addr << " " << static_cast<int32_t>(tramp_addr - (func_ptr + 5)) << std::endl;
//         std::cout << "tramp bytes: ";
//         print_bytes(tramp_addr, 30);
//         std::cout << "new bytes: ";
//         print_bytes(func_ptr, 10);
//     }

//     mprotect(slab, SLAB_SIZE, PROT_READ | PROT_EXEC);
// }