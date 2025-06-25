cmake_minimum_required(VERSION 3.15)
project(PanoptesContainer)

# Set C++17 as required
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Source files
set(SOURCES
    src/container.cpp
    src/ext_server.cpp
    ../../proto/build/panoptes.grpc.pb.cc
    ../../proto/build/panoptes.pb.cc
)

# Header files
set(HEADERS
    include/container.h
    include/container_ipc.hpp
    ../../proto/build/panoptes.grpc.pb.h
    ../../proto/build/panoptes.pb.h
)

# Create executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/proto/build
    ${CMAKE_SOURCE_DIR}/src/extensibility/shared
    ${CMAKE_SOURCE_DIR}/src/container/include
)

# Link libraries
target_link_libraries(${PROJECT_NAME} 
PRIVATE
    gRPC::gpr 
    gRPC::grpc 
    gRPC::grpc++ 
    gRPC::grpc++_alts
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE Crypt32)
endif()

# Set output directories to match Visual Studio structure
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
)

# Set static runtime for MSVC
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
