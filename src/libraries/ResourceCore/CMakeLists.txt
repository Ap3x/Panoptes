cmake_minimum_required(VERSION 4.0)
project(Resources CXX)

# Source files
set(SOURCES
    src/ResourceCore.cpp
)

set(HEADERS
    include/ResourceCore.h
    include/Resource.rc
)

# Create shared library (DLL)
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

# Define RESOURCES_EXPORTS for DLL exports
target_compile_definitions(${PROJECT_NAME} PRIVATE RESOURCES_EXPORTS)

# Include directories
target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set Windows specific properties
if(MSVC)
    # Set properties for MSVC
    set_target_properties(${PROJECT_NAME} PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
    )
endif()

# Installation
install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(FILES 
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ResourceCore.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/resource.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
) 

# Set output directories
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}"
)

