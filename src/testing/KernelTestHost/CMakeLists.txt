cmake_minimum_required(VERSION 4.0)

# Project name and language
project(KernelTestHost 
        VERSION 1.0
        LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define source files
set(SOURCES
    "src/KernelTestHost.cpp"
    "src/panoptes_trace.cpp"
)

set(HEADERS
    "include/panoptes_trace.h"
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set output directories to match the MSVC structure
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/$<CONFIG>/testing)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/$<CONFIG>/testing)

# Windows-specific settings
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        UNICODE
        _UNICODE
        $<$<CONFIG:Debug>:_DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
    )
    
    # Set debug information generation
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "ProgramDatabase")
    else()
        set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "None")
    endif()
endif()

# Set warning level to match MSVC settings
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W3)
endif()
