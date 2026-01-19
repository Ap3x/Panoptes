cmake_minimum_required(VERSION 4.0)
project(Test_PanoptesYara)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set static runtime for MSVC - MUST BE SET BEFORE ANY TARGETS
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    # Set linker flags
    # /MANIFEST - Enables manifest generation for the executable
    # /NXCOMPAT - Enables Data Execution Prevention (DEP) compatibility
    # /DYNAMICBASE - Enables Address Space Layout Randomization (ASLR)
    # /OPT:REF - Eliminates functions and data that are never referenced
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /OPT:REF")
endif()

set(YARA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../external/yara-x-capi-v1.1.0-x86_64-pc-windows-msvc)

find_package(gRPC CONFIG REQUIRED)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)

# Use static CRT to match the rest of the project
set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

set(SOURCES
    "Test_PanoptesYara.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/yara-scan.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/../include/PanoptesYara.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../shared/ExtensibilityCore.h"
    "${YARA_DIR}/yara_x.h"
)

add_executable(Test_PanoptesYara ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../shared"
        "${YARA_DIR}"
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    X64
    NDEBUG
    _CONSOLE
    _UNICODE
    UNICODE
)

target_link_libraries(${PROJECT_NAME} PRIVATE GTest::gtest_main)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    ntdll 
    Crypt32
)
target_link_libraries(${PROJECT_NAME} PUBLIC ${YARA_DIR}/yara_x_capi.lib)

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/tests/$<CONFIG>"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/tests/$<CONFIG>"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/tests/$<CONFIG>"
)

if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )

    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
endif()

include(GoogleTest)
gtest_discover_tests(Test_PanoptesYara)

# Copy test files to runtime directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_SOURCE_DIR}/assets/yara/rules.pkg"
        "${CMAKE_SOURCE_DIR}/bin/tests/$<CONFIG>/rules.pkg"
    COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_SOURCE_DIR}/assets/yara/eicarcom2.zip"
        "${CMAKE_SOURCE_DIR}/bin/tests/$<CONFIG>/eicarcom2.zip"
)

# Update link directories
target_link_directories(${PROJECT_NAME} PRIVATE
    "${YARA_DIR}"
)