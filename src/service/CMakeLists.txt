cmake_minimum_required(VERSION 3.15)
project(PanoptesService VERSION 1.0.0 LANGUAGES CXX)

# Set C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(gRPC CONFIG REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(RocksDB CONFIG REQUIRED)

set(PROTO_FILE "${CMAKE_SOURCE_DIR}/proto/src/panoptes.proto")

# Define source files
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/containers.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/database.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/driver.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/events.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/grpc.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/pano_log.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/error_message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mutex.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/service.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/PanoptesService.rc
    ${PROTO_FILE}
)

# Define header files
set(HEADERS
    ${CMAKE_CURRENT_SOURCE_DIR}/include/containers.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/database.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/driver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/events.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/grpc.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/icon_resource.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/pano_log.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/mutex.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/service_constants.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/error_message.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/hash.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/panoptes_service.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/utils.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../libraries/ResourceCore/include/ResourceCore.h
)

# Create executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})

if(BUILD_GRPC)
    find_package(gRPC CONFIG REQUIRED)

    # Set proto file path
    set(PROTO_FILE_DIR "${CMAKE_SOURCE_DIR}/proto/src/")
    set(PROTO_BUILD_DIR "${CMAKE_SOURCE_DIR}/proto/build")

    # Create build directory if it doesn't exist
    file(MAKE_DIRECTORY ${PROTO_BUILD_DIR})

    message("   --> PROTOBUF LIB: ${PROTOBUF_LIBRARIES}")
    message("   --> PROTOBUF INCLUDE: ${Protobuf_INCLUDE_DIRS}")
    message("   --> PROTOBUF VERSION: ${Protobuf_VERSION}")
    message("   --> PROTOBUF Found: ${Protobuf_FOUND}")
    message("   --> PROTOBUF SRC: ${PROTO_SRC}")
    message("   --> PROTOBUF HEADER: ${PROTO_HEADER}")
    message("   --> PROTOBUF Folder: ${CMAKE_BINARY_DIR}/proto")
    
    #target_link_libraries(${PROJECT_NAME} PUBLIC protobuf::libprotobuf gRPC::grpc++)
    
    set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    
    target_include_directories(${PROJECT_NAME} PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

    protobuf_generate(
        TARGET ${PROJECT_NAME}
        IMPORT_DIRS ${PROTO_FILE_DIR}
        PROTOC_EXE "${Protobuf_PROTOC_EXECUTABLE}"
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
    )
    
    protobuf_generate(
        TARGET ${PROJECT_NAME}
        LANGUAGE grpc
        PROTOC_EXE "${Protobuf_PROTOC_EXECUTABLE}"
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
        PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
        IMPORT_DIRS ${PROTO_FILE_DIR}
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
    )
endif()

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../driver/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/build
    ${CMAKE_CURRENT_SOURCE_DIR}/../../external
    ${CMAKE_CURRENT_SOURCE_DIR}/../libraries/ResourceCore/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../libraries/Configuration/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../libraries/TrayNotificationsCore/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../extensibility/PanoptesAMSI/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../extensibility/shared
    ${CMAKE_SOURCE_DIR}/assets/icons
    # ${CMAKE_CURRENT_SOURCE_DIR}/../extensibility/PE/include
    # ${CMAKE_CURRENT_SOURCE_DIR}/../extensibility/Yara/include
    ${INTERFACE_INCLUDE_DIRECTORIES}
)

# Link internal libraries
add_dependencies(${PROJECT_NAME}
    Configuration
    TrayNotificationsCore
)

target_link_libraries(${PROJECT_NAME} PRIVATE RocksDB::rocksdb)

target_link_libraries(${PROJECT_NAME} PRIVATE
    gRPC::gpr 
    gRPC::grpc 
    gRPC::grpc++ 
    gRPC::grpc++_alts
    nlohmann_json::nlohmann_json
)
target_link_libraries(${PROJECT_NAME} PRIVATE
    Configuration
    TrayNotificationsCore
    Crypt32
    Shlwapi
    Rpcrt4
    Tdh
)

# Configure preprocessor definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
    $<$<CONFIG:Debug>:SODIUM_STATIC=1>
    $<$<CONFIG:Debug>:SODIUM_EXPORT=>
    NOMINMAX
)

# Set output directories

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
) 

# Post-build command to copy config file
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_SOURCE_DIR}/assets/panoptes.config
    $<TARGET_FILE_DIR:${PROJECT_NAME}>/panoptes.config
)

if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        LINK_FLAGS "/SUBSYSTEM:WINDOWS"
        WIN32_EXECUTABLE TRUE
    )
endif()


