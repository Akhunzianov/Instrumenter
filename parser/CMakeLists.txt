add_library(parser_lib STATIC
  src/Factory.cpp
  src/ElfParser.cpp
  src/main.cpp
)

find_path(ELF_INCLUDE_DIR elf.h
  HINTS /opt/homebrew/include /usr/local/include
)

if (NOT ELF_INCLUDE_DIR)
  message(FATAL_ERROR "elf.h not found")
endif()

target_include_directories(parser_lib
  PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${ELF_INCLUDE_DIR}
)

add_executable(parser_exec
  src/main.cpp
)

target_link_libraries(parser_exec
  PRIVATE parser_lib
)