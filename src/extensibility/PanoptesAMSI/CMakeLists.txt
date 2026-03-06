cmake_minimum_required(VERSION 3.15)
project(PanoptesAMSI)

# Set C++17 as required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(gRPC CONFIG REQUIRED)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(test)
endif()

set(PROTO_FILE "${CMAKE_SOURCE_DIR}/proto/src/panoptes.proto")

# Define source files
file(GLOB SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
    ${PROTO_FILE}
)

# Define header files
file(GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared/*.h
    ${PROTO_FILE}
)

# Create the shared library
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

if(BUILD_GRPC)
    find_package(gRPC CONFIG REQUIRED)

    # Set proto file path
    set(PROTO_FILE_DIR "${CMAKE_SOURCE_DIR}/proto/src/")
    set(PROTO_BUILD_DIR "${CMAKE_SOURCE_DIR}/proto/build")

    # Create build directory if it doesn't exist
    file(MAKE_DIRECTORY ${PROTO_BUILD_DIR})

    message("   --> PROTOBUF LIB: ${PROTOBUF_LIBRARIES}")
    message("   --> PROTOBUF INCLUDE: ${Protobuf_INCLUDE_DIRS}")
    message("   --> PROTOBUF VERSION: ${Protobuf_VERSION}")
    message("   --> PROTOBUF Found: ${Protobuf_FOUND}")
    message("   --> PROTOBUF SRC: ${PROTO_SRC}")
    message("   --> PROTOBUF HEADER: ${PROTO_HEADER}")
    message("   --> PROTOBUF Folder: ${CMAKE_BINARY_DIR}/proto")
    
    #target_link_libraries(${PROJECT_NAME} PUBLIC protobuf::libprotobuf gRPC::grpc++)
    
    set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    
    target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

    protobuf_generate(
        TARGET ${PROJECT_NAME}
        IMPORT_DIRS ${PROTO_FILE_DIR}
        PROTOC_EXE "${Protobuf_PROTOC_EXECUTABLE}"
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
    )
    
    protobuf_generate(
        TARGET ${PROJECT_NAME}
        LANGUAGE grpc
        PROTOC_EXE "${Protobuf_PROTOC_EXECUTABLE}"
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
        PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
        IMPORT_DIRS ${PROTO_FILE_DIR}
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
    )
endif()

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared
    ${PROTO_BINARY_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts)
target_link_libraries(${PROJECT_NAME} PRIVATE amsi Shlwapi Crypt32)

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
) 

# Windows-specific configurations
if(WIN32)
    # Add PANOPTESAMSI_EXPORTS define for DLL exports
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        PANOPTESAMSI_EXPORTS
        _WINDOWS
        _USRDLL
    )
    
    # Set static runtime library for all configurations
    if(MSVC)
        set_property(TARGET ${PROJECT_NAME} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
    $<$<CONFIG:Test>:NDEBUG>
)

# Disable generating debug info for Release and Test configurations
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES 
        LINK_FLAGS_RELEASE "/DEBUG:NONE"
        LINK_FLAGS_TEST "/DEBUG:NONE"
    )
endif()

# Add post-build command to copy DLL to ext directory for Debug configuration
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/bin/Debug/ext"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${PROJECT_NAME}>"
        "${CMAKE_SOURCE_DIR}/bin/Debug/ext/$<TARGET_FILE_NAME:${PROJECT_NAME}>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_PDB_FILE:${PROJECT_NAME}>"    
        "${CMAKE_SOURCE_DIR}/bin/Debug/ext/$<TARGET_PDB_FILE_NAME:${PROJECT_NAME}>"
    COMMENT "Copying ${PROJECT_NAME} DLL and PDB to ext directory"
) 