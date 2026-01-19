cmake_minimum_required(VERSION 3.15)
project(Panoptes VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_DOC "Build documentation" OFF)
option(BUILD_WIX_INSTALLER "Build Wix installer package" OFF)
option(BUILD_DRIVER "Build driver package" OFF)
option(BUILD_GRPC "Generate gRPC code" ON)

find_package(Doxygen)
if (DOXYGEN_FOUND AND BUILD_DOC)
    set(DOXYGEN_IN ${CMAKE_SOURCE_DIR}/docs/Doxyfile)

    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( doc_doxygen ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_IN}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/docs
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
elseif(DOXYGEN_FOUND AND NOT BUILD_DOC)
    message("Doxygen needs to be installed to generate the doxygen documentation")
endif(DOXYGEN_FOUND AND BUILD_DOC)


#add_subdirectory(src/service)
#add_subdirectory(src/libraries)

#add_subdirectory(src/extensibility)
#add_subdirectory(src/container)
#add_subdirectory(src/dll)
#add_subdirectory(src/linter)
#add_subdirectory(src/scanner)
add_subdirectory(src/testing)

if(BUILD_DRIVER)
    add_subdirectory(src/driver)
endif()

if(BUILD_WIX_INSTALLER)
    add_subdirectory(installer/Setup)
    add_subdirectory(installer/Wix)
endif()
