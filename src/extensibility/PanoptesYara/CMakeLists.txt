cmake_minimum_required(VERSION 3.15)
project(PanoptesYara)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # Set linker flags to match VS configuration
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST /NXCOMPAT /DYNAMICBASE /DEBUG /LTCG:STATUS /INCREMENTAL /SUBSYSTEM:WINDOWS /MANIFESTUAC:NO /NOLOGO /TLBID:1")
    
    # Enable Link Time Code Generation
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

set(YARA_DIR ${CMAKE_SOURCE_DIR}/external/yara-x-capi-v1.1.0-x86_64-pc-windows-msvc)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(test)
endif()

find_package(gRPC CONFIG REQUIRED)

set(PROTO_FILE "${CMAKE_SOURCE_DIR}/proto/src/panoptes.proto")

# Define source files
file(GLOB SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dllmain.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/yara-scan.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/service_client_yara.cpp
    ${PROTO_FILE}
)

# Define header files
set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/PanoptesYara.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/ExtensibilityCore.h"
    "${YARA_DIR}/yara_x.h"
)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

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


target_compile_definitions(${PROJECT_NAME} PRIVATE
    _UNICODE
    UNICODE
)

# if(MSVC)
#     target_compile_options(${PROJECT_NAME} PRIVATE
#         /MP
#         /EHsc
#     )
# endif()

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared   
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build
    ${YARA_DIR}
)

# Link libraries - adding all required system libraries
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        protobuf::libprotobuf
        gRPC::grpc++
        ntdll 
        Crypt32
        kernel32
        user32
        gdi32
        winspool
        comdlg32
        advapi32
        shell32
        ole32
        oleaut32
        uuid
        odbc32
        odbccp32
        ${YARA_DIR}/yara_x_capi.lib
)

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>"
) 

# Add post-build command to copy DLL to ext directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/ext"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:${PROJECT_NAME}>"
        "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/ext/$<TARGET_FILE_NAME:${PROJECT_NAME}>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_PDB_FILE:${PROJECT_NAME}>"
        "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/ext/$<TARGET_PDB_FILE_NAME:${PROJECT_NAME}>"
    COMMENT "Copying ${PROJECT_NAME} DLL and PDB to ext directory"
) 