cmake_minimum_required(VERSION 3.20)

# Project name and language
project(PanoptesSetup
        VERSION 1.0
        LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(absl CONFIG REQUIRED)

# Add executable
add_executable(PanoptesSetup WIN32 src/PanoptesSetup.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE
    absl::flags
    absl::flags_parse
    Crypt32
)

# Configure for Windows
if(WIN32)
    # Use Unicode character set
    target_compile_definitions(PanoptesSetup PRIVATE UNICODE _UNICODE)
    
    # Link required Windows libraries
    target_link_libraries(PanoptesSetup PRIVATE setupapi)
    
    # Set static runtime library
    set_property(TARGET PanoptesSetup PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_include_directories(PanoptesSetup PRIVATE ${CATCH_INCLUDE_DIR})

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
)

# Configure specific settings for different configurations
foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG} CONFIG_UPPER)
    if(${CONFIG} STREQUAL "Test")
        # Test configuration inherits from Release with debug info
        set(CMAKE_C_FLAGS_${CONFIG_UPPER} ${CMAKE_C_FLAGS_RELEASE})
        set(CMAKE_CXX_FLAGS_${CONFIG_UPPER} ${CMAKE_CXX_FLAGS_RELEASE})
        set_target_properties(PanoptesSetup PROPERTIES
            COMPILE_DEFINITIONS_${CONFIG_UPPER} "NDEBUG"
        )
    endif()
endforeach()
