cmake_minimum_required(VERSION 3.15)
project(PanoptesAMSI)

# Set C++17 as required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(gRPC CONFIG REQUIRED)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(test)
endif()

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

# Create the shared library
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build
    ${CMAKE_CURRENT_SOURCE_DIR}/../shared
)

target_link_libraries(${PROJECT_NAME} PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts)
target_link_libraries(${PROJECT_NAME} PRIVATE amsi Shlwapi Crypt32)

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