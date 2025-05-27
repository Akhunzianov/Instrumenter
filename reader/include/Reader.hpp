#pragma once

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <vector>

#include "Instrument.hpp"

class Reader {
public:
    Reader(std::unique_ptr<Instrument> inst) : real_instrument(std::move(inst)) {}

    void execute();

private:
    std::string executable_path;
    std::unique_ptr<Instrument> real_instrument;
};