cmake_minimum_required(VERSION 3.15)
project(Test_Service)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Service code without dependencies on the driver, gRPC or the database, compiled directly
add_executable(Test_Service
  Test_ProcessImages.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/process_images.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../src/utils.cpp
)
target_include_directories(Test_Service PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_compile_definitions(Test_Service PRIVATE NOMINMAX)
target_link_libraries(Test_Service GTest::gtest_main Shlwapi)

set_target_properties(Test_Service PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/tests"
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

include(GoogleTest)
gtest_discover_tests(Test_Service)
