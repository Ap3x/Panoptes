cmake_minimum_required(VERSION 3.15)
project(PanoptesLinter CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(nlohmann_json REQUIRED)

# Set static runtime for MSVC - MUST BE SET BEFORE ANY TARGETS
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    foreach(flag_var
        CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
        CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/test)

# For non-MSVC compilers
if(NOT MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

# Add source files
set(SOURCES
    src/PanoptesLinter.cpp
)

# Add header files
set(HEADERS
    include/PanoptesLinter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/../libraries/Configuration/include/Configuration.hpp
)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

add_dependencies(${PROJECT_NAME} Configuration)

# Add include directories
target_include_directories(${PROJECT_NAME} 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_SOURCE_DIR}/../libraries/Configuration/include
        ${INTERFACE_INCLUDE_DIRECTORIES}
)

# Link dependencies
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        nlohmann_json::nlohmann_json
        Configuration
)

# Set properties for MSVC
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
) 