cmake_minimum_required(VERSION 4.0)
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

# Define source files
file(GLOB SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/*.cc
)

# Define header files
file(GLOB HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared/*.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/*.h
)

# Create shared library
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build
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