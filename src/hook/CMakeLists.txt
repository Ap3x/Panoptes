cmake_minimum_required(VERSION 3.21)
project(PanoptesDLL
    VERSION 1.0
    DESCRIPTION "Panoptes DLL Project"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable static linking for both architectures
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Source files
set(SOURCES
    src/dllmain.cpp
    src/hook.cpp
    src/hook_trace.cpp
)

set(HEADERS
    include/def.h
    include/framework.h
    include/hook.hpp
    include/hook_trace.hpp
)

# Output directory. The x86 sub-build passes the main project's bin directory in,
# so both DLLs land side by side in bin/<config>
if(NOT DEFINED PANOPTES_BIN_DIR)
    set(PANOPTES_BIN_DIR "${CMAKE_SOURCE_DIR}/bin")
endif()

# A single Visual Studio generator only targets one platform, so the DLL is built for
# whatever platform this project was configured with (Detours comes from the matching
# vcpkg triplet)
function(configure_target TARGET_NAME)
    # Set Detours paths for this architecture. The vcpkg triplet ships separate
    # release and debug libraries, which must match the configuration's CRT
    find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
    find_library(DETOURS_LIBRARY_RELEASE detours
        PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/lib"
        NO_DEFAULT_PATH REQUIRED)
    find_library(DETOURS_LIBRARY_DEBUG detours
        PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/lib"
        NO_DEFAULT_PATH REQUIRED)
    set(DETOURS_LIBRARY optimized ${DETOURS_LIBRARY_RELEASE} debug ${DETOURS_LIBRARY_DEBUG})

    # Create target
    add_library(${TARGET_NAME} SHARED
        ${SOURCES}
        ${HEADERS}
        assets/resource.rc
    )

    # Set output names and directories
    set_target_properties(${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "${TARGET_NAME}"
        RUNTIME_OUTPUT_DIRECTORY "${PANOPTES_BIN_DIR}/${PRESET_NAME}")

    # Include directories
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${DETOURS_INCLUDE_DIRS}
    )

    # Link dependencies
    target_link_libraries(${TARGET_NAME} PRIVATE ${DETOURS_LIBRARY})

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
endfunction()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    configure_target(${PROJECT_NAME}x64)
else()
    configure_target(${PROJECT_NAME}x86)
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif()

# When configured as x64 from the main project, build the x86 DLL as a separate Win32
# sub-build of this directory. It uses the root vcpkg.json with only its "hook" feature, so
# only Detours is installed for x86-windows-static, at the same version as the x64 DLL
if(CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT PROJECT_IS_TOP_LEVEL)
    include(ExternalProject)

    ExternalProject_Add(${PROJECT_NAME}x86
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
        BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/x86"
        CMAKE_GENERATOR "${CMAKE_GENERATOR}"
        CMAKE_GENERATOR_PLATFORM Win32
        CMAKE_ARGS
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
            -DVCPKG_TARGET_TRIPLET=x86-windows-static
            -DVCPKG_MANIFEST_DIR=${CMAKE_SOURCE_DIR}
            -DVCPKG_MANIFEST_NO_DEFAULT_FEATURES=ON
            -DVCPKG_MANIFEST_FEATURES=hook
            -DPANOPTES_BIN_DIR=${PANOPTES_BIN_DIR}
            -DPRESET_NAME=${PRESET_NAME}
            -DBUILD_TESTS=${BUILD_TESTS}
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
        INSTALL_COMMAND ""
        BUILD_ALWAYS ON
    )
endif()
