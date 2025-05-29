# Contributing to This Project

Thank you for your interest in contributing! We welcome pull requests, issues, and suggestions to help improve this binary instrumentation framework.

Please read the guidelines below to get started.

---

## 🛠 General Contribution Guidelines

- All contributions should go through Pull Requests (PRs).
- Code should follow the existing formatting style (indentation, naming, etc.).
- Add comments and documentation for new public methods or architecture-specific logic.
- Test your changes with a representative binary (preferably one using basic libc symbols).

---

## 🧱 Adding Support for a New Architecture

This project currently supports `x86_64`. To add support for a new architecture (e.g., ARM64, RISC-V), you'll need to modify several parts of the codebase.

The most critical file is:

### ✅ `ArchUtils.hpp`

This file contains architecture-specific logic for:

- Reading and writing the **program counter (PC / RIP / EIP / etc.)**
- Reading the **general-purpose registers**
- Enabling and disabling breakpoints (`int3` / equivalent)
- Printing registers
- Configuring disassembler (Capstone) and assembler (Keystone)

### Steps to Add a New Architecture:

1. **Extend the `ArchTypes` enum** (e.g., `ARM64`, `RISCV`) in `Parser.hpp`. And add corresponding arch parse handling in `load` function for parsers.
2. **Add Capstone/Keystone support**:
   - Update `get_capstone_config()` and `get_keystone_config()` in `ArchUtils.hpp`:
     ```cpp
     case ARM64:
         return {CS_ARCH_ARM64, CS_MODE_ARM};
     ```
3. **Handle registers** in:
   - `get_registers(pid_t&)`
   - `get_program_counter(pid_t&)`
   - `set_program_counter(pid_t&, uint64_t&)`
   - `print_registers(pid_t&)`
   - Use `#ifdef` for platform/architecture checks.
4. **Implement breakpoint injection logic**:
   - Update `enable_breakpoint()` and `disable_breakpoint()`
   - Architecture-specific instructions may differ (e.g., not just `0xCC`)
5. **Test your implementation** with minimal binaries compiled for that architecture.

If you're unsure about any part — feel free to open a draft PR or ask via issues.

---

## 📄 Files You May Need to Touch

| File                | Purpose                                              |
|---------------------|------------------------------------------------------|
| `ArchUtils.hpp`     | Core architecture-specific logic                     |
| `Parser.hpp`        | Add enum entries for `ArchTypes`                     |
| `Breakpointer.cpp`  | Only if stepping or `ptrace` behavior varies         |
| `Disassembler.cpp`  | Only if Capstone requires different disassembly flow |

---

## 📬 Submitting a Pull Request

1. Fork the repo
2. Create a new branch: `git checkout -b feat/arch-arm64`
3. Make your changes and commit with clear messages
4. Push to your fork: `git push origin feat/arch-arm64`
5. Open a Pull Request and describe your changes clearly

---

## 🧩 Adding Support for a New Binary Format

This project currently supports ELF binaries only. You can extend the `Parser` infrastructure to support other executable formats such as **Mach-O**, **PE (Windows)**, or custom binary formats.

### 🔍 Key Files

| File                          | Purpose                                                   |
|-------------------------------|-----------------------------------------------------------|
| `Parser.hpp`                 | Defines the abstract interface for all parsers            |
| `createParser()`             | Factory function that detects the format and instantiates a parser |
| `ElfParser.hpp / ElfParser.cpp` | Implementation of the ELF parser                         |
| `types.hpp`                  | Format-agnostic data types (Section, Segment, Symbol...)  |

---

### 🧱 Steps to Add a New Format

#### 1. **Extend the `FileTypes` Enum**

In `Parser.hpp`:

```cpp
enum FileTypes {
    ELF,
    MACHO,   // or PE, BIN, etc.
};
```

#### 2. **Implement a New Parser Subclass**

Create a new parser like `MachoParser`:

```cpp
class MachoParser : public Parser {
public:
    void load(const std::string& path) override;
    std::vector<Section>& get_sections() const override;
    std::vector<Segment>& get_segments() const override;
    std::vector<Symbol>& get_symbols() const override;
    std::vector<Relocation>& get_relocations() const override;
    std::vector<Symbol>& get_functions() const override;
    uint64_t get_function_vaddr(Symbol func) const override;
    uint8_t* get_function_ptr(const Symbol& func) const override;
    uint64_t get_vacant_vaddr() const override;
    uint64_t get_code_start_vaddr() const override;
};
```

You must fill in `sections_cache`, `segments_cache`, etc., exactly like in `ElfParser`.

#### 3. **Update the `createParser()` Factory Function**

In `ParserFactory.cpp`:

```cpp
if (memcmp(magic, "\xFE\xED\xFA\xCE", 4) == 0) {
    return std::make_unique<MachoParser>();
}
```

Use proper magic numbers or detection logic for your format.

#### 4. **Use Existing Format-Agnostic Types**

Use `Section`, `Segment`, `Symbol`, and `Relocation` from `types.hpp`.

If your format has additional metadata, store it in the `extra` fields:

```cpp
section.extra["alignment"] = "16";
symbol.extra["scope"] = "weak";
```

---


### 🧠 Example: Adding Mach-O Support

1. Add `MACHO` to `FileTypes`
2. Create `MachoParser.hpp/cpp` implementing `Parser`
3. Modify `createParser()` to detect Mach-O via magic number
4. Use `mach-o/loader.h` or equivalent APIs for parsing
5. Populate format-independent structures from your Mach-O data

---

### 📌 Tip

You can use `ElfParser` as a working reference when building your own parser.

If you need help with format parsing or want a `MachoParser` or `PeParser` template — feel free to open an issue or draft PR!

---

## 🧠 Extending Behavior with Weak Functions

The instrumenter provides several `weak`-defined C-style hooks that allow you to **override behavior without changing the core logic**. These hooks are already supported and integrated into the build system.

### 🔄 Supported Hooks

These functions can be optionally overridden:

```cpp
extern "C" void set_ptrace_flags(pid_t pid);
extern "C" void before_run_ptrace(pid_t pid);
extern "C" void on_breakpoint_ptrace(pid_t pid, breakpoint_t& bp);
extern "C" void clean_up_ptrace(pid_t pid);
```

---

### 📁 Using `user.cpp` for Quick Experiments

A default file `user.cpp` is already present in the repository and included in the build.  
It is intended for quick customization and local development. You can override any of the above weak functions in this file:

```cpp
extern "C" void on_breakpoint_ptrace(pid_t pid, breakpoint_t& bp) {
    printf("Custom breakpoint at 0x%lx\n", bp.bp_addr);
}
```

🚫 Please **do not modify `user.cpp`** directly when contributing new features or behaviors.

---

### 🌿 Contributing Custom Overrides

If you've developed a useful override (e.g., for tracing, analysis, logging), follow this process:

1. **Create a new file**, e.g. `my_hook.cpp`.
2. **Add it to the build system** (e.g. `CMakeLists.txt`) by analogy with `user.cpp`.
3. **Override desired `weak` functions** in your file.
4. **Open a Pull Request (PR)** with only your new file — do not touch `user.cpp`.

This way, `user.cpp` remains a stable placeholder for personal use and a good example for newcommers, while your contribution can be properly reviewed, tested, and merged.

## 🐛 Bug Reports

If you encounter a bug:

1. Please create a [GitHub issue](https://github.com/your/repo/issues/new).
2. Include the steps to reproduce, and attach relevant binary files if possible.
3. Mention your OS, architecture, and binary format.

---

## 🚀 Suggesting New Features

Feel free to:

- Open a feature request issue.
- Submit a pull request implementing a useful feature.

Make sure to:

- Follow the existing coding style.
- Document new options or behaviors.
- Add comments if introducing architecture or format-specific logic.

---

## 🙌 Thanks

We appreciate all contributions — whether fixing typos, improving documentation, or extending the tool!

Happy hacking 🧠

Thank you for contributing to this project! 💻
