cmake_minimum_required(VERSION 4.0)
project(Configuration CXX)

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

set(RESOURCES_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ResourceCore/include" )
find_package(nlohmann_json REQUIRED)

set(SOURCES
    src/Configuration.cpp
)

set(HEADERS
    include/Configuration.hpp
)

# Create shared library
add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
        nlohmann_json::nlohmann_json
)

# Include directories
target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${PANOPTES_INCLUDE_DIR}
        ${EXTERNAL_INCLUDE_DIR}
        ${RESOURCES_INCLUDE_DIR}
        ${INTERFACE_INCLUDE_DIRECTORIES}
)

# Set properties for MSVC
if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )
endif()

# Installation
install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install public headers
file(GLOB PUBLIC_HEADERS "*.h")
install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
) 