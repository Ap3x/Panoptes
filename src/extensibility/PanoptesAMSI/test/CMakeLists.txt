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

set(SOURCES
    "Test_PanoptesAMSI.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/service_client_amsi.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../src/amsi-scan.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../proto/build/panoptes.grpc.pb.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../proto/build/panoptes.pb.cc"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/../include/PanoptesAMSI.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../shared/ExtensibilityCore.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../proto/build/panoptes.grpc.pb.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../proto/build/panoptes.pb.h"
)

add_executable(Test_PanoptesAMSI ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME} 
    PRIVATE 
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../shared"
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../../proto/build" 
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
