cmake_minimum_required(VERSION 3.13)
project(PanoptesService)

set(LIB_PATH 
    "${CMAKE_SOURCE_DIR}/static/libyara64.lib"
    "wintrust"
    "Shlwapi"
    "ImageHlp"
)

set(YARA_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/static/libyara/include")

target_include_directories(PanoptesService PUBLIC
    "${YARA_INCLUDE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_sources(PanoptesService 
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/agent.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/inject.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pe.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/pipe.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/token.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/src/vt_yara.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/assets/resource.rc
)

set_target_properties(PanoptesService PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin
    OUTPUT_NAME "PanoptesService"
)

target_link_libraries(PanoptesService ${LIB_PATH})

