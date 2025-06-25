cmake_minimum_required(VERSION 3.15)
project(PanoptesYara)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # Set linker flags to match VS configuration
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST /NXCOMPAT /DYNAMICBASE /DEBUG /LTCG:STATUS /INCREMENTAL /SUBSYSTEM:WINDOWS /MANIFESTUAC:NO /NOLOGO /TLBID:1")
    
    # Enable Link Time Code Generation
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

set(YARA_DIR ${CMAKE_SOURCE_DIR}/external/yara-x-capi-v1.1.0-x86_64-pc-windows-msvc)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(test)
endif()

find_package(gRPC CONFIG REQUIRED)

# Define source files
file(GLOB SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dllmain.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/yara-scan.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/service_client_yara.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.grpc.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.pb.cc
)

# Define header files
set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/PanoptesYara.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../shared/ExtensibilityCore.h"
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.grpc.pb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.pb.h
    "${YARA_DIR}/yara_x.h"
)

add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

target_compile_definitions(${PROJECT_NAME} PRIVATE
    _UNICODE
    UNICODE
)

# if(MSVC)
#     target_compile_options(${PROJECT_NAME} PRIVATE
#         /MP
#         /EHsc
#     )
# endif()

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared   
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build
    ${YARA_DIR}
)

# Link libraries - adding all required system libraries
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        protobuf::libprotobuf
        gRPC::grpc++
        ntdll 
        Crypt32
        kernel32
        user32
        gdi32
        winspool
        comdlg32
        advapi32
        shell32
        ole32
        oleaut32
        uuid
        odbc32
        odbccp32
        ${YARA_DIR}/yara_x_capi.lib
)

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
) 

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