cmake_minimum_required(VERSION 3.15)
project(PanoptesScan VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_PREFIX_PATH "B:/vcpkg_installed/x64-windows-static")
set(Protobuf_PROTOC_EXECUTABLE "B:/vcpkg_installed/x64-windows-static/tools/protobuf/protoc.exe")
find_package(gRPC CONFIG REQUIRED)

# Source files
set(SOURCES
    src/scan.cpp
    src/scanner_ipc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.grpc.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.pb.cc
)

# Header files
set(HEADERS
    include/scanner_ipc.hpp
    include/resource.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.grpc.pb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build/panoptes.pb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/PanoptesScan.rc
)

# Create executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS} )

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../proto/build
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    gRPC::gpr 
    gRPC::grpc 
    gRPC::grpc++ 
    gRPC::grpc++_alts
    Crypt32
)

# Set output directories to match the vcxproj configuration
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
)

# Add icon resource
set(APP_ICON "${CMAKE_CURRENT_SOURCE_DIR}/../../../assets/icons/panoptes-head.ico")
if(EXISTS ${APP_ICON})
    target_sources(${PROJECT_NAME} PRIVATE ${APP_ICON})
endif()

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
        
        # Set Windows subsystem
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS")
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