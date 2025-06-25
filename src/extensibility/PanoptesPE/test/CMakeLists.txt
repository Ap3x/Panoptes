cmake_minimum_required(VERSION 4.0)
project(Test_PanoptesPE)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# LIEF build config. Set the default options for LIEF's project setup
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)

set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")
set(LIEF_VERSION 0.16.5)

include(FetchContent)
FetchContent_Declare(LIEF
    GIT_REPOSITORY  "${LIEF_GIT_URL}"
    GIT_TAG         ${LIEF_VERSION}
)

FetchContent_MakeAvailable(LIEF)

find_package(gRPC CONFIG REQUIRED)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Define source files
set(SOURCES
    Test_PanoptesPE.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/pe-scan.cpp
)

# Define header files
set(HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/../include/PanoptesPE.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shared/ExtensibilityCore.h
)

# Create executable instead of shared library
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../shared
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../../external/LIEF-0.16.5-win64/LIEF-0.16.5-win64/include
)

# Add compiler definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    X64
    NDEBUG
    _CONSOLE
    _UNICODE
    UNICODE
)

target_link_libraries(${PROJECT_NAME} PRIVATE GTest::gtest_main LIEF::LIEF Crypt32)

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/tests"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/tests"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/tests"
) 

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "CRT option")
       
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
endif()

include(GoogleTest)
gtest_discover_tests(Test_PanoptesPE)
