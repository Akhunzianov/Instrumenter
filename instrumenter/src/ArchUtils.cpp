#include "ArchUtils.hpp"

std::pair<cs_arch, cs_mode> get_capstone_config(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return {CS_ARCH_X86, CS_MODE_64};
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}

std::pair<ks_arch, ks_mode> get_keystone_config(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return {KS_ARCH_X86, KS_MODE_64};
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}

char* get_asm_back_trampoline(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return (
                "push rax ; "
                "push edi ; "
                "push rdi ; "
                "mov edi, 0x%08X ; "
                "mov rax, 0x%llx ; "
                "call rax ; "
                "pop rdi ; "
                "pop edi ; "
                "mov rax, 0x%llx ; "
                "jmp rax ; "
            );
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}

char* get_asm_front_trampoline(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return (
                "pop rax ; "
            );
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}

char* get_asm_event(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return (
                "push rcx ; "
                "push rax ; "
                "push rdx ; "
                "push r8 ; "

                "mov rcx, rdi ; "
                "shl rcx, 3 ; "
                "mov rax, 0x%llx ; "
                "add rax, rcx ; "
                "inc QWORD PTR [rax] ; "

                "mov r8, QWORD PTR [rax] ; "
                "mov rcx, r8 ; "
                "mov rbx, %u ; "
                "xor rdx, rdx ; "
                "div rbx ; "
                "test rdx, rdx ; "
                // "jnz" // TODO: add relative jump to skip syscall if not enough calls made

                "sub rsp, 16 ; "
                "mov DWORD PTR [rsp], edi ; "
                "mov QWORD PTR [rsp+4], r8 ; "

                "mov rax, 1 ; "
                "mov rdi, %d ; "
                "mov rsi, rsp ; "
                "mov rdx, 12 ; "
                "syscall ; "

                "pop r8 ; "
                "pop rdx ; "
                "pop rax ; "
                "pop rcx ; "
                "ret ; "
            );
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}

char* get_asm_prologue(ArchTypes archType) {
    switch (archType) {
        case X86_64:
            return (
                "push rax ; "
                "mov rax, 0x%llx ; "
                "jmp rax ; "
                "pop rax ; "
            );
            break;
        
        default:
            throw std::invalid_argument("Unknown architecture");
            break;
    }
}
