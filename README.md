Вот английская версия твоего README в формате Markdown:

# 🔧 Instrumenter

**Instrumenter** is a utility for static and dynamic analysis of binary files, with support for inserting and tracking breakpoints in executable code.  
Currently supports ELF files and the `x86_64` architecture.

---

## 📦 Features

* Disassembles the `.text` section using Capstone
* Detects function calls (`call`) and sets breakpoints
* Supports PIE (Position-Independent Executables)
* Interactive execution mode with function/return tracing
* Easily extensible via `weak` functions in `user.cpp`

---

## 🚀 Quick Start

```bash
# Clone the repository
$ git clone https://github.com/Akhunzianov/Instrumenter.git
$ cd Instrumenter

# Build
$ make
```

---

## 🔧 Usage

This tool has two main modes of operation: analysis and instrumentation.

---

## 🔍 Analysis Mode

Used to inspect the structure of an ELF binary without executing it.

```
./instrumenter_exec ./path/to/binary.elf [options]
```

### Options:
-	`--no-sections` – Skip displaying ELF sections
-	`--no-segments` – Skip displaying program segments
-	`--no-symbols` – Skip displaying symbol table
-	`--no-relocs` – Skip displaying relocations
- `-h, --help` – Show this help message and exit

### Example:
```
./instrumenter_exec ./examples/test.elf --no-symbols
```

---

## 🧪 Instrumentation Mode

Runs the target binary under ptrace with automatic breakpoint insertion.
Can be used to trace function calls and optionally dump register values. 
If file contains symbol information then at the function call will be accounted 
and the will be displayed in a readable format. If file however does not contain symbols
the disassembly will take place and functions will be named automatically as `f_<numder>`
```
./instrumenter_exec --print-regs ./path/to/binary.elf [args...]
```
### Options:
-	`--print-regs` – Print register values at each breakpoint (call or return)
-	`[args...]` – Arguments passed to the target binary

### Example:
```
./instrumenter_exec --print-regs ./examples/test.elf arg1 arg2
```
This runs test.elf with arguments and prints register dumps on breakpoint hits.

### More examples

```bash
➜  Instrumenter git:(main) ✗ ./instrumenter_exec --print-regs ./dummy.elf
breakpoint at [0x401020]   call: _start 

========== Register Dump (PID: 1669) ==========
   reg   hex                  dec
----------------------------------------------
   RIP   0x0000000000401021   4198433
   RSP   0x00007ffe426a3f10   140730012679952
   RBP   0x0000000000000000   0
   RAX   0x0000000000000038   56
   RBX   0x0000000000000000   0
   RCX   0x00007ffe426a3f28   140730012679976
   RDX   0x00007a0fee8eb380   134208845427584
   RSI   0x00007a0fee91f8b8   134208845641912
   RDI   0x00007a0fee91f2e0   134208845640416
    R8   0x00007ffe426a4660   140730012681824
    R9   0x00007a0fee91c440   134208845628480
   R10   0x00007ffe426a3b10   140730012678928
   R11   0x0000000000000203   515
   R12   0x0000000000401020   4198432
   R13   0x00007ffe426a3f10   140730012679952
   R14   0x0000000000000000   0
   R15   0x0000000000000000   0
----------------------------------------------
...

```
```bash
➜  Instrumenter git:(main) ✗ ./instrumenter_exec ./dummy_nopie.elf 
breakpoint at [0x401020]   call: _start 
breakpoint at [0x401000]   call: _init 
breakpoint at [0x401100]   call: frame_dummy 
breakpoint at [0x401090]   call: register_tm_clones 
breakpoint at [0x401180]   call: main 
breakpoint at [0x401106]   call: _Z4fooov 
breakpoint at [0x401151]   call: _Z4barrv 
breakpoint at [0x4010d0]   call: __do_global_dtors_aux 
breakpoint at [0x401060]   call: deregister_tm_clones 
breakpoint at [0x4011b8]   call: _fini 

```

```bash
➜  Instrumenter git:(main) ✗ ./parser_exec ./dummy.elf --no-sections --no-relocs --no-symbols 

Segments:

Type                Flags   Offset      VMA         LMA         Filesz      Memsz       Extra

PHDR                R       0x40        0x40        0x40        728         728         align=8          
INTERP              R       0x318       0x318       0x318       28          28          align=1          
LOAD                R       0x0         0x0         0x0         1520        1520        align=4096       
LOAD                RE      0x1000      0x1000      0x1000      513         513         align=4096       
LOAD                R       0x2000      0x2000      0x2000      276         276         align=4096       
LOAD                RW      0x2df0      0x3df0      0x3df0      544         552         align=4096       
DYNAMIC             RW      0x2e00      0x3e00      0x3e00      448         448         align=8          
NOTE                R       0x338       0x338       0x338       48          48          align=8          
NOTE                R       0x368       0x368       0x368       68          68          align=4          
UNKNOWN             R       0x338       0x338       0x338       48          48          align=8          
GNU_EH_FRAME        R       0x2004      0x2004      0x2004      60          60          align=4          
GNU_STACK           RW      0x0         0x0         0x0         0           0           align=16         
GNU_RELRO           R       0x2df0      0x3df0      0x3df0      528         528         align=1  

```
```bash
➜  Instrumenter git:(main) ./instrumenter_exec /bin/ps 
breakpoint at [0x567aadb8d59b]   call: f_95084900568800 
breakpoint at [0x567aadb95b8c]   call: f_95084900593616 
breakpoint at [0x567aadb95508]   call: f_95084900593616 
breakpoint at [0x567aadb95527]   call: f_95084900593616 
breakpoint at [0x567aadb9562d]   call: f_95084900593616 
breakpoint at [0x567aadb90b9e]   call: f_95084900583312 
    PID TTY          TIME CMD
breakpoint at [0x567aadb8ecb3]   call: f_95084900574608 
   1237 pts/1    00:00:00 sudo
breakpoint at [0x567aadb8ecb3]   call: f_95084900574608 
   1238 pts/1    00:00:00 su
breakpoint at [0x567aadb8ecb3]   call: f_95084900574608 
   1239 pts/1    00:00:00 bash
breakpoint at [0x567aadb8ecb3]   call: f_95084900574608 
   1246 pts/1    00:00:00 zsh
breakpoint at [0x567aadb8ecb3]   call: f_95084900574608 
   1896 pts/1    00:00:00 instrumenter_ex
breakpoint at [0x567aadb8ecb3]   call: f_95084900574608 
   1897 pts/1    00:00:00 ps
breakpoint at [0x567aadb94087]   call: f_95084900597744 
breakpoint at [0x567aadb940a7]   call: f_95084900597744 
[+] process 1897 terminated

```

### Note
feel free to test `example.elf` and other files yourself

---

## 🧩 Overriding Weak Functions

The project defines several `weak` functions that you can override to customize the behavior of the instrumentation engine.

These include:

```cpp
extern "C" void set_ptrace_flags(pid_t pid);
extern "C" void before_run_ptrace(pid_t pid);
extern "C" void on_breakpoint_ptrace(pid_t pid, breakpoint_t& bp);
extern "C" void clean_up_ptrace(pid_t pid);
```
But feel free to add your own

### ✅ Default Override File: user.cpp

The repository already includes a user.cpp file that is added to build. You can use this file to implement your own behavior. For example:

```cpp
extern "C" void on_breakpoint_ptrace(pid_t pid, breakpoint_t& bp) {
    printf("Hit breakpoint at 0x%lx\n", bp.bp_addr);
}
```
These functions provide you with a large specter of capabillities as you can utilize `ptrace` functions 
inside them to get basically any info about running binary (e.g. read basic and float registers, memmory, etc). 
Learn more about [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)

---

## 🔗 Dependencies

This project relies on the following external libraries and tools:

### 🧱 Libraries

| Library        | Purpose                                           |
|----------------|---------------------------------------------------|
| **Capstone**   | Disassembly of machine instructions               | 
| **Keystone**   | Assembly of machine instructions                  |
| **C++ STL**    | Standard containers, strings, streams, etc.       | 

> ✅ **Capstone** is used to disassembly machine-level instructions in binaries.

> ❗️ **Keystone** is not used right now but is included for possible futere use

---

### 🛠 Install Dependencies

```
# Capstone
apt install libcapstone-dev

# Keystone
git clone https://github.com/keystone-engine/keystone.git /opt/keystone && \
cd /opt/keystone && \
mkdir build && cd build && \
cmake .. && \
make -j$(nproc) && \
make install && \
ldconfig
```
- Note that some headers (e.g. `elf.h` may not be present or lack some defenitions on differens systems)

---

## ℹ️ Notes
- Only ELF binaries for supported architectures (currently x86_64) are accepted
- Check if `ptrace` is availible on your platform to understand if the tool will work properly
- `ptrace` may not work properly with containers

---

## ⚙️ Supported Architectures
-	x86_64
## ⚙️ Supported Executable formats
-	ELF

## Want to Add a New Architecture?
See CONTRIBUTING.md

---

## 🐞 Bug Reports & Pull Requests
-	Found a bug? Open an issue-
-	Want to add features? Fork → branch → PR
-	Remember to update README.md and CONTRIBUTING.md if needed
