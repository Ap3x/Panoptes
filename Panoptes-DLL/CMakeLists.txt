cmake_minimum_required(VERSION 3.13)
project(Panoptes-DLL)

set(LIB_PATH 
    "${CMAKE_SOURCE_DIR}/static/detours.lib"
    "${CMAKE_SOURCE_DIR}/static/libyara64.lib"
    "wintrust"
    "Shlwapi"
    "ImageHlp"
)
set(DETOURS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/static/include")
set(YARA_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/static/libyara/include")

include_directories(include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

target_include_directories(Panoptes-DLL PUBLIC    
    "${DETOURS_INCLUDE_DIR}"
    "${YARA_INCLUDE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_sources(Panoptes-DLL 
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/dllmain.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hook.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vt_yara.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/assets/resource.rc
)

set_target_properties(Panoptes-DLL PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    OUTPUT_NAME "Panoptes"
)

target_link_libraries(Panoptes-DLL ${LIB_PATH})

