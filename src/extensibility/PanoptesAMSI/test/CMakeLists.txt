cmake_minimum_required(VERSION 3.15)
project(Test_PanoptesAMSI)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(gRPC CONFIG REQUIRED)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

set(PROTO_FILE "${CMAKE_SOURCE_DIR}/proto/src/panoptes.proto")

set(SOURCES
    "Test_PanoptesAMSI.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/service_client_amsi.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/amsi-scan.cpp"
    ${PROTO_FILE}
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/../include/PanoptesAMSI.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../shared/ExtensibilityCore.h"
)

add_executable(Test_PanoptesAMSI ${SOURCES} ${HEADERS})

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
    
    target_link_libraries(${PROJECT_NAME} PUBLIC protobuf::libprotobuf gRPC::grpc++)
    
    set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
    
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

target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../shared"
        ${PROTO_BINARY_DIR}
)
    
target_link_libraries(${PROJECT_NAME} PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts GTest::gtest_main)
target_link_libraries(${PROJECT_NAME} PRIVATE amsi Shlwapi Crypt32)

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/tests"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/tests"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/tests"
) 

if(MSVC)
    # Set static runtime library for all configurations
    set_property(TARGET ${PROJECT_NAME} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        
    # Additional MSVC-specific flags for static linking
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:Debug>:/MTd>
    )
endif()

include(GoogleTest)
gtest_discover_tests(Test_PanoptesAMSI)
