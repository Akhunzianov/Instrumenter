#pragma once

#include <vector>
#include <string>

#include "types.hpp"

namespace parser
{

class Parser {
public:
    virtual ~Parser() = default;
    virtual void load(const std::string& path) = 0;
    virtual std::vector<Section> get_sections() const = 0;
    virtual std::vector<Segment> get_segments() const = 0;
    virtual std::vector<Symbol> get_symbols() const = 0;
    virtual std::vector<Relocation> get_relocations() const = 0;
};

std::unique_ptr<Parser> createParser(const std::string& path);

} // namespace parser