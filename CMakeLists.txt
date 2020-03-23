cmake_minimum_required(VERSION 3.14)
project(beacon_core)

set(CMAKE_CXX_STANDARD 17)

if (NOT EXISTS "${CMAKE_SOURCE_DIR}/cryptopp/CMakeLists.txt")
    file(DOWNLOAD https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/CMakeLists.txt "${CMAKE_SOURCE_DIR}/cryptopp/CMakeLists.txt" SHOW_PROGRESS)
    file(DOWNLOAD https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/cryptopp-config.cmake "${CMAKE_SOURCE_DIR}/cryptopp/cryptopp-config.cmake" SHOW_PROGRESS)
endif ()

add_subdirectory(cryptopp)

include_directories(include)

add_executable(beacon_core library.cpp library.h src/crypto/keys.cpp include/crypto/keys.h)
target_link_libraries(beacon_core cryptopp-static)
