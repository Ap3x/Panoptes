cmake_minimum_required(VERSION 3.15)
project(PanoptesPE)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(test)
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
    # Set compiler flags to match msbuild configuration
    # set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")
    # set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MDd")

    # Set linker flags
    # /MANIFEST - Enables manifest generation for the executable
    # /NXCOMPAT - Enables Data Execution Prevention (DEP) compatibility
    # /DYNAMICBASE - Enables Address Space Layout Randomization (ASLR)
    # /OPT:REF - Eliminates functions and data that are never referenced
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /OPT:REF")
endif()


# LIEF build config. Set the default options for LIEF's project setup
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)


# URL of the LIEF repo (Can be your fork)
set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")
# LIEF's version to be used (can be 'main')
set(LIEF_VERSION 0.16.5)

  include(FetchContent)
  FetchContent_Declare(LIEF
    GIT_REPOSITORY  "${LIEF_GIT_URL}"
    GIT_TAG         ${LIEF_VERSION}
    # You may specify an existing LIEF source directory if you don't want to
    # download. Just comment out the above ``GIT_*`` commands and uncoment the
    # following ``SOURCE_DIR`` line
    #SOURCE_DIR      "${CMAKE_CURRENT_LIST_DIR}/../../.."
    )

FetchContent_MakeAvailable(LIEF)

find_package(gRPC CONFIG REQUIRED)

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
)

# Create shared library
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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../external/LIEF-0.16.5-win64/LIEF-0.16.5-win64/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE LIEF::LIEF Crypt32)
target_link_libraries(${PROJECT_NAME} PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts)

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