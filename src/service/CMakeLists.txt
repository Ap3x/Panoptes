cmake_minimum_required(VERSION 3.15)
project(PanoptesService VERSION 1.0.0 LANGUAGES CXX)

# Set C++20 standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(gRPC CONFIG REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(RocksDB CONFIG REQUIRED)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/build/panoptes.grpc.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/build/panoptes.pb.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/include/PanoptesService.rc
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
    ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/build/panoptes.grpc.pb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/build/panoptes.pb.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../libraries/ResourceCore/include/ResourceCore.h
)

# Create executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCES} ${HEADERS})

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


