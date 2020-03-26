cmake_minimum_required(VERSION 3.10)
project(beacon_core)

set(CMAKE_CXX_STANDARD 17)

if (NOT EXISTS "${CMAKE_SOURCE_DIR}/cryptopp/CMakeLists.txt")
    if (EXISTS "${CMAKE_SOURCE_DIR}/cryptopp/.travis.yml")
        file(DOWNLOAD https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/CMakeLists.txt "${CMAKE_SOURCE_DIR}/cryptopp/CMakeLists.txt" SHOW_PROGRESS)
        file(DOWNLOAD https://raw.githubusercontent.com/noloader/cryptopp-cmake/master/cryptopp-config.cmake "${CMAKE_SOURCE_DIR}/cryptopp/cryptopp-config.cmake" SHOW_PROGRESS)
    else ()
        message(FATAL_ERROR "CryptoPP not found! Make sure you do: git submodule init; git submodule update")
    endif ()
endif ()

add_subdirectory(cryptopp)

include_directories(include)

add_executable(beacon_core library.cpp library.h src/crypto/keys.cpp include/crypto/keys.h src/crypto/encrypt.cpp include/crypto/encrypt.h)
target_link_libraries(beacon_core cryptopp-static)
