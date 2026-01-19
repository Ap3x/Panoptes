cmake_minimum_required(VERSION 3.15)
project(PanoptesContainer)

# Set C++17 as required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

set(PROTO_FILE "${CMAKE_SOURCE_DIR}/proto/src/panoptes.proto")

# Source files
set(SOURCES
    src/container.cpp
    src/ext_server.cpp
    ${PROTO_FILE}
)

# Header files
set(HEADERS
    include/container.h
    include/container_ipc.hpp
)

# Create executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})

if(BUILD_GRPC)
    find_package(Protobuf CONFIG REQUIRED)
    find_package(gRPC CONFIG REQUIRED)

    # Set proto file path
    set(PROTO_SRC "${CMAKE_SOURCE_DIR}/proto/src")
    set(PROTO_FILE "${PROTO_SRC}/panoptes.proto")
    set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")

    # Generated file paths
    set(PROTO_PB_CC "${PROTO_OUT_DIR}/panoptes.pb.cc")
    set(PROTO_PB_H "${PROTO_OUT_DIR}/panoptes.pb.h")
    set(PROTO_GRPC_CC "${PROTO_OUT_DIR}/panoptes.grpc.pb.cc")
    set(PROTO_GRPC_H "${PROTO_OUT_DIR}/panoptes.grpc.pb.h")

    # Find protoc executable
    find_program(PROTOC_EXECUTABLE protoc REQUIRED)

    message("   --> PROTOBUF LIB: ${PROTOBUF_LIBRARIES}")
    message("   --> PROTOBUF INCLUDE: ${Protobuf_INCLUDE_DIRS}")
    message("   --> PROTOBUF VERSION: ${Protobuf_VERSION}")
    message("   --> PROTOBUF Found: ${Protobuf_FOUND}")
    message("   --> PROTO_FILE: ${PROTO_FILE}")
    message("   --> Protobuf Compiler: ${PROTOC_EXECUTABLE}")

    # Create custom command for protobuf generation
    add_custom_command(
        OUTPUT ${PROTO_PB_CC} ${PROTO_PB_H}
        COMMAND ${PROTOC_EXECUTABLE}
        ARGS --cpp_out=${PROTO_OUT_DIR}
             -I${PROTO_SRC}
             ${PROTO_FILE}
        DEPENDS ${PROTO_FILE}
        COMMENT "Running protobuf compiler on ${PROTO_FILE}"
        VERBATIM
    )

    # Create custom command for gRPC generation
    add_custom_command(
        OUTPUT ${PROTO_GRPC_CC} ${PROTO_GRPC_H}
        COMMAND ${PROTOC_EXECUTABLE}
        ARGS --grpc_out=${PROTO_OUT_DIR}
             --plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>
             -I${PROTO_SRC}
             ${PROTO_FILE}
        DEPENDS ${PROTO_FILE} ${PROTO_PB_CC} gRPC::grpc_cpp_plugin
        COMMENT "Running gRPC compiler on ${PROTO_FILE}"
        VERBATIM
    )

    # Add generated files as source to the target
    target_sources(${PROJECT_NAME} PRIVATE
        ${PROTO_PB_CC}
        ${PROTO_GRPC_CC}
    )

    # Add include directory for generated files
    target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${PROTO_OUT_DIR}>")

    # Link protobuf and gRPC libraries
    target_link_libraries(${PROJECT_NAME} PRIVATE protobuf::libprotobuf)
endif()

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/extensibility/shared
    ${CMAKE_SOURCE_DIR}/src/container/include
)

# Link libraries
target_link_libraries(${PROJECT_NAME} 
PRIVATE
    gRPC::gpr 
    gRPC::grpc 
    gRPC::grpc++ 
    gRPC::grpc++_alts
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Crypt32)
endif()

# Set output directories to match Visual Studio structure
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>"
)

# Set static runtime for MSVC
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
