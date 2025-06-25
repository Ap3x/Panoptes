cmake_minimum_required(VERSION 4.0)
project(Test_PanoptesYara)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

set(YARA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../external/yara-x-capi-v1.1.0-x86_64-pc-windows-msvc)

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
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/tests"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/tests"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/tests"
) 

include(GoogleTest)
gtest_discover_tests(Test_PanoptesYara)

# Copy test files to runtime directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_SOURCE_DIR}/assets/yara/rules.pkg"
        "${CMAKE_SOURCE_DIR}/bin/tests/${CMAKE_BUILD_TYPE}/rules.pkg"
    COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_SOURCE_DIR}/assets/yara/eicarcom2.zip"
        "${CMAKE_SOURCE_DIR}/bin/tests/${CMAKE_BUILD_TYPE}/eicarcom2.zip"
)

# Update link directories
target_link_directories(${PROJECT_NAME} PRIVATE
    "${YARA_DIR}"
)