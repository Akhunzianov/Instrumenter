#pragma once

#include <string>
#include <cstdio>
#include <map>
#include <memory>


struct Section {
    std::string name;
    std::intptr_t offset, addr;
    int32_t size;
    std::map<std::string, std::string> extra;
};

struct Segment {
    std::string type, flags;
    int64_t offset, vma, lma, filesize, memsize; 
    std::map<std::string, std::string> extra;
};

struct Symbol {
    std::string name, bind, visibility, type;
    std::intptr_t value;
    int32_t size = 0;
    std::map<std::string, std::string> extra;
};

struct Relocation {
    std::intptr_t offset, info;
    std::string type, symbol_name;
    std::map<std::string, std::string> extra;
};
