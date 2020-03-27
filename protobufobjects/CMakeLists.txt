if (NOT EXISTS "${CMAKE_SOURCE_DIR}/protobuf/cmake/CMakeLists.txt")
    message(FATAL_ERROR "protobuf not found! Make sure you do git submodule update --init --recursive")
endif()
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(${CMAKE_SOURCE_DIR}/protobuf/cmake ${CMAKE_BINARY_DIR}/protobuf)
project(beacon_protobufobjects)

set(PROTOBUF_FILES message.proto)
foreach(pb_file ${PROTOBUF_FILES})
    string(REPLACE ".proto" ".pb.h" pb_header ${pb_file})
    string(REPLACE ".proto" ".pb.cc" pb_source ${pb_file})
    list(APPEND PROTOBUF_HEADERS "${CMAKE_CURRENT_BINARY_DIR}/${pb_header}")
    list(APPEND PROTOBUF_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/${pb_source}")
endforeach()

message("${PROTOBUF_HEADERS}")
message("${PROTOBUF_SOURCES}")

add_custom_command(OUTPUT ${PROTOBUF_HEADERS} ${PROTOBUF_SOURCES}
        COMMAND $<TARGET_FILE:protoc> ARGS --proto_path=${CMAKE_CURRENT_SOURCE_DIR} --cpp_out=${CMAKE_CURRENT_BINARY_DIR} ${PROTOBUF_FILES}
        DEPENDS $<TARGET_FILE:protoc> ${PROTOBUF_FILES})

add_library(protobufobjects ${PROTOBUF_SOURCES})
target_link_libraries(protobufobjects
        PUBLIC protobuf::libprotobuf)
target_include_directories(protobufobjects
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_library(beacon::protobufobjects ALIAS protobufobjects)