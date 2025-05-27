cmake_minimum_required(VERSION 3.18)
project(parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)

add_subdirectory(parser)
add_subdirectory(instrumenter)
add_subdirectory(reader)