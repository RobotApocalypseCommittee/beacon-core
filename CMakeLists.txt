# cmake_minimum_required(VERSION <specify CMake version here>)
project(beacon_core)

set(CMAKE_CXX_STANDARD 17)

add_library(beacon_core library.cpp library.h)