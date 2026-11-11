cmake_minimum_required(VERSION 3.15)
project(Test_Linter)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force static runtime libraries
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Static runtime for MSVC


enable_testing()

add_executable(
  Test_Linter
  Test_Linter.cpp
)
find_package(nlohmann_json REQUIRED)

target_link_libraries(
  Test_Linter
  GTest::gtest_main
  Configuration
  nlohmann_json::nlohmann_json
)

# The ShippedConfiguration tests check the configuration that is shipped
target_compile_definitions(Test_Linter PRIVATE
  PANOPTES_SHIPPED_CONFIG="${CMAKE_SOURCE_DIR}/assets/panoptes.config"
)

set_target_properties(Test_Linter PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/tests"
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
gtest_discover_tests(Test_Linter)

