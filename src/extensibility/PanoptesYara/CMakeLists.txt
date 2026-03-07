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

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(YARA_DIR ${CMAKE_SOURCE_DIR}/external/yara-x-capi-v1.14.0-x86_64-pc-windows-msvc)

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
        PROTOC_EXE "${CMAKE_BINARY_DIR}/${Protobuf_PROTOC_EXECUTABLE}"
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
    )
    
    protobuf_generate(
        TARGET ${PROJECT_NAME}
        LANGUAGE grpc
        PROTOC_EXE "${CMAKE_BINARY_DIR}/${Protobuf_PROTOC_EXECUTABLE}"
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
        PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
        IMPORT_DIRS ${PROTO_FILE_DIR}
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
    )
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
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
) 

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