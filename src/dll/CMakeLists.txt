cmake_minimum_required(VERSION 4.0)
project(PanoptesDLL
    VERSION 1.0
    DESCRIPTION "Panoptes DLL Project"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable static linking for both architectures
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Build Detours library from source
add_subdirectory(Detours-build)

# Source files
set(SOURCES
    src/dllmain.cpp
    src/hook.cpp
)

set(HEADERS
    include/def.h
    include/framework.h
    include/hook.hpp
)

# Function to configure target for specific architecture
function(configure_target TARGET_NAME ARCH)
    if(ARCH STREQUAL "x64")
        set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
        set(OUTPUT_SUFFIX "x64")
    else()
        set(VCPKG_TARGET_TRIPLET "x86-windows-static" CACHE STRING "")
        set(OUTPUT_SUFFIX "x86")
    endif()

    # Create target
    add_library(${TARGET_NAME} SHARED
        ${SOURCES}
        ${HEADERS}
        assets/resource.rc
    )

    # Set output names and directories
    set_target_properties(${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "${PROJECT_NAME}${OUTPUT_SUFFIX}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>")

    # Include directories
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/Detours/src
    )

    # Link dependencies against locally built Detours library
    target_link_libraries(${TARGET_NAME} PRIVATE lib_detours)

    # Compiler definitions
    target_compile_definitions(${TARGET_NAME} PRIVATE
        $<$<CONFIG:Debug>:_DEBUG>
        $<$<CONFIG:Release,Test>:NDEBUG>
        PANOPTESDLL_EXPORTS
        _WINDOWS
        _USRDLL
        WIN32_LEAN_AND_MEAN
    )

    # MSVC specific settings
    if(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE
            /W3
            $<$<CONFIG:Release,Test>:/O2>
            $<$<CONFIG:Release,Test>:/Oi>
            $<$<CONFIG:Release,Test>:/GL>
        )
        
        target_link_options(${TARGET_NAME} PRIVATE
            $<$<CONFIG:Release,Test>:/LTCG>
            $<$<CONFIG:Release>:/DEBUG:NONE>
        )
    endif()

    # Sign DLL using the same certificate as the Driver
    if(ARCH STREQUAL "x64")
        add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
            COMMAND "${x64_BUILD_TOOLS_PATH}/signtool.exe" sign /a /v /fd sha256 /s PanoptesCertStore /n "Panoptes" /t http://timestamp.digicert.com "$<TARGET_FILE:${TARGET_NAME}>"
            COMMENT "Signing the DLL"
        )
    else()
        add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
            COMMAND "${x86_BUILD_TOOLS_PATH}signtool.exe" sign /a /v /fd sha256 /s PanoptesCertStore /n "Panoptes" /t http://timestamp.digicert.com "$<TARGET_FILE:${TARGET_NAME}>"
            COMMENT "Signing the DLL"
        )
    endif()
endfunction()

# Create x64 and x86 targets
configure_target(${PROJECT_NAME}x64 "x64")
configure_target(${PROJECT_NAME}x86 "x86")
