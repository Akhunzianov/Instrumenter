add_library(instrumenter_lib STATIC
  src/Instrument.cpp
  src/ArchUtils.cpp 
  src/Breakpointer.cpp
  src/Disassembler.cpp
  src/main.cpp
)

find_library(CAPSTONE_LIB capstone 
  HINTS /usr/lib /usr/local/lib
)
find_path(CAPSTONE_INCLUDE_DIR capstone 
  HINTS /opt/homebrew/include /usr/local/include
)

if (NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIB)
  message(FATAL_ERROR "capstone not found")
endif()

find_library(KEYSTONE_LIB keystone 
  HINTS /usr/lib /usr/local/lib
)
find_path(KEYSTONE_INCLUDE_DIR keystone 
  HINTS /opt/homebrew/include /usr/local/include
)

if (NOT KEYSTONE_INCLUDE_DIR OR NOT KEYSTONE_LIB)
  message(FATAL_ERROR "keystone not found")
endif()

target_include_directories(instrumenter_lib
  PUBLIC
    ${CMAKE_SOURCE_DIR}/parser/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CAPSTONE_INCLUDE_DIR}
    ${KEYSTONE_INCLUDE_DIR}
)

add_executable(instrumenter_exec
  src/main.cpp
)

target_link_libraries(instrumenter_exec
  PRIVATE 
    instrumenter_lib
    parser_lib
    ${CAPSTONE_LIB}
    ${KEYSTONE_LIB}
)
