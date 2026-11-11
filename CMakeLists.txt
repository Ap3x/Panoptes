cmake_minimum_required(VERSION 3.15)

# Components to build. Each has a matching feature in vcpkg.json listing only the packages it
# needs
option(BUILD_SERVICE "Build PanoptesService (gRPC, RocksDB, nlohmann-json)" ON)
option(BUILD_CONTAINER "Build PanoptesContainer (gRPC)" ON)
option(BUILD_YARA "Build the PanoptesYara extension (gRPC)" ON)
option(BUILD_SCANNER "Build PanoptesScan and PanoptesScanCLI (gRPC, nlohmann-json)" ON)
option(BUILD_LINTER "Build PanoptesLinter (nlohmann-json)" ON)
option(BUILD_HOOK "Build the x64 and x86 hook DLLs (Detours)" ON)
option(BUILD_DETECTOR "Build PanoptesDetector, the behavioral rule engine (needs Go)" ON)

option(BUILD_DOC "Build documentation" OFF)
option(BUILD_WIX_INSTALLER "Build Wix installer package" OFF)
option(BUILD_DRIVER "Build driver package" OFF)
option(BUILD_GRPC "Generate gRPC code" ON)
option(BUILD_TESTS "Build unit tests into bin/<config>/tests" OFF)

# The installer packages every component
if(BUILD_WIX_INSTALLER)
    foreach(COMPONENT SERVICE CONTAINER YARA SCANNER LINTER HOOK)
        if(NOT BUILD_${COMPONENT})
            message(FATAL_ERROR "BUILD_WIX_INSTALLER packages every component, so it needs BUILD_${COMPONENT}")
        endif()
    endforeach()
endif()

# vcpkg installs the manifest's packages when project() runs, so the features must be chosen
# before it. Only the enabled components' features are installed. These are recomputed on every
# configure, so set the BUILD_<COMPONENT> options rather than VCPKG_MANIFEST_FEATURES. Turning a
# component off in an existing build directory makes vcpkg remove its packages there (turning it
# back on restores them from the vcpkg binary cache)
set(PANOPTES_VCPKG_FEATURES)
foreach(COMPONENT SERVICE CONTAINER YARA SCANNER LINTER HOOK)
    if(BUILD_${COMPONENT})
        string(TOLOWER ${COMPONENT} FEATURE)
        list(APPEND PANOPTES_VCPKG_FEATURES ${FEATURE})
    endif()
endforeach()
if(BUILD_WIX_INSTALLER)
    list(APPEND PANOPTES_VCPKG_FEATURES installer)
endif()
set(VCPKG_MANIFEST_NO_DEFAULT_FEATURES ON CACHE BOOL "Set from the BUILD_<COMPONENT> options" FORCE)
set(VCPKG_MANIFEST_FEATURES "${PANOPTES_VCPKG_FEATURES}" CACHE STRING "Set from the BUILD_<COMPONENT> options" FORCE)

project(Panoptes VERSION 1.0.0 LANGUAGES CXX)

# Use extraction time for URL downloads (silences FetchContent CMP0135 warning)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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


# ResourceCore and Configuration (nlohmann-json) are used by the service and the linter
if(BUILD_SERVICE OR BUILD_LINTER)
    add_subdirectory(src/libraries)
endif()
if(BUILD_SERVICE)
    add_subdirectory(src/service)
endif()
if(BUILD_YARA)
    add_subdirectory(src/extensibility)
endif()
if(BUILD_CONTAINER)
    add_subdirectory(src/container)
endif()
if(BUILD_HOOK)
    add_subdirectory(src/hook)
endif()
if(BUILD_LINTER)
    add_subdirectory(src/linter)
endif()
if(BUILD_DETECTOR)
    add_subdirectory(src/detector)
endif()
if(BUILD_SCANNER)
    add_subdirectory(src/scanner)
endif()

if(BUILD_DRIVER)
    add_subdirectory(src/driver)
endif()

# Debug builds also produce bin/TargetPackage.zip, everything needed to run Panoptes on a
# separate KDNET target machine. Other configurations run an empty command. It packages the
# driver with every component except the linter, so it is only created when they are all built
if(BUILD_DRIVER AND BUILD_SERVICE AND BUILD_CONTAINER AND BUILD_YARA AND BUILD_SCANNER AND BUILD_HOOK)
    add_custom_target(TargetPackage ALL
        COMMAND "$<$<CONFIG:Debug>:powershell.exe;-NoProfile;-ExecutionPolicy;Bypass;-File;${CMAKE_SOURCE_DIR}/.vscode/package-target.ps1;-ToolsDir;${x64_BUILD_TOOLS_PATH};-Zip>"
        COMMAND_EXPAND_LISTS
        VERBATIM
        COMMENT "Packaging the Debug build for the KDNET target"
    )
    add_dependencies(TargetPackage
        PanoptesService
        PanoptesContainer
        PanoptesYara
        PanoptesScan
        PanoptesScanCLI
        Resources
        PanoptesDLLx64
        PanoptesDLLx86
        PanoptesDriver
    )
    # The service starts the detector when it is next to it; packages without it still run
    if(BUILD_DETECTOR)
        add_dependencies(TargetPackage PanoptesDetector)
    endif()

    # With BUILD_TESTS, the package also carries the hook tests. The x64 ones are targets here;
    # the x86 ones are built by the PanoptesDLLx86 sub-build above
    get_property(HOOK_TEST_TARGETS GLOBAL PROPERTY PANOPTES_HOOK_TEST_TARGETS)
    if(HOOK_TEST_TARGETS)
        add_dependencies(TargetPackage ${HOOK_TEST_TARGETS})
    endif()
elseif(BUILD_DRIVER)
    message(STATUS "Not creating TargetPackage: it needs every component except the linter")
endif()

if(BUILD_WIX_INSTALLER)
    add_subdirectory(installer/Setup)
    add_subdirectory(installer/Wix)
endif()
