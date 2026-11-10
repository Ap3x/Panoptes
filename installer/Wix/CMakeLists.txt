cmake_minimum_required(VERSION 3.20)
project(PanoptesInstaller)

set(WIX_VERSION "5.0.2")

if(NOT BUILD_DRIVER)
    message(FATAL_ERROR "BUILD_WIX_INSTALLER requires BUILD_DRIVER=ON (the MSI packages the signed driver)")
endif()

find_program(WIX_COMMAND wix.exe
    PATHS "$ENV{USERPROFILE}/.dotnet/tools"
    DOC "Path to WiX v5 command-line tool")

if(NOT WIX_COMMAND)
    message(FATAL_ERROR "WiX v5 Toolset not found. Please install using: dotnet tool install --global wix --version ${WIX_VERSION}")
endif()

# Make sure the WiX extensions used by the package are in the global extension cache
set(WIX_EXTENSIONS
    WixToolset.UI.wixext
    WixToolset.Util.wixext
)

execute_process(
    COMMAND ${WIX_COMMAND} extension list -g
    OUTPUT_VARIABLE WIX_INSTALLED_EXTENSIONS
    ERROR_QUIET
)

foreach(EXT ${WIX_EXTENSIONS})
    if(NOT WIX_INSTALLED_EXTENSIONS MATCHES "${EXT} ${WIX_VERSION}")
        message(STATUS "Installing WiX extension ${EXT}/${WIX_VERSION}")
        execute_process(
            COMMAND ${WIX_COMMAND} extension add -g ${EXT}/${WIX_VERSION}
            RESULT_VARIABLE WIX_EXT_RESULT
        )
        if(NOT WIX_EXT_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to install WiX extension ${EXT}/${WIX_VERSION}")
        endif()
    endif()
endforeach()

# Output to bin/<config>/installer alongside the rest of the build output
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/installer")

# Define WiX source files
set(WIX_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/AppComponents.wxs
    ${CMAKE_CURRENT_SOURCE_DIR}/Execute.wxs
    ${CMAKE_CURRENT_SOURCE_DIR}/Folders.wxs
    ${CMAKE_CURRENT_SOURCE_DIR}/Package.en-us.wxl
    ${CMAKE_CURRENT_SOURCE_DIR}/Package.wxs
)

# Targets whose outputs are packaged into the MSI
set(PACKAGED_TARGETS
    PanoptesService
    PanoptesContainer
    PanoptesDLLx64
    PanoptesDLLx86
    Resources
    PanoptesYara
    PanoptesLinter
    PanoptesScan
    PanoptesScanCLI
    PanoptesSetup
    PanoptesDriver
)

set(PACKAGED_FILES)
foreach(TGT ${PACKAGED_TARGETS})
    get_target_property(TGT_TYPE ${TGT} TYPE)
    if(TGT_TYPE STREQUAL "UTILITY")
        # ExternalProject builds (the x86 hook DLL) have no TARGET_FILE
        list(APPEND PACKAGED_FILES "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/${TGT}.dll")
    else()
        list(APPEND PACKAGED_FILES $<TARGET_FILE:${TGT}>)
    endif()
endforeach()

# Create custom command for WiX v5 build
add_custom_command(
    OUTPUT ${OUTPUT_DIR}/PanoptesInstaller.msi
    COMMAND ${CMAKE_COMMAND} -E make_directory ${OUTPUT_DIR}
    COMMAND ${WIX_COMMAND} build
        -arch x64
        -ext WixToolset.UI.wixext/${WIX_VERSION}
        -ext WixToolset.Util.wixext/${WIX_VERSION}
        -bindpath "${CMAKE_SOURCE_DIR}/assets/yara"
        -bindpath "${CMAKE_SOURCE_DIR}/assets"
        -bindpath "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>"
        -bindpath "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/driver"
        -bindpath "${CMAKE_SOURCE_DIR}/src/service/assets"
        -bindpath "${CMAKE_CURRENT_SOURCE_DIR}/assets"
        ${WIX_SOURCES}
        -o ${OUTPUT_DIR}/PanoptesInstaller.msi
    DEPENDS ${WIX_SOURCES} ${PACKAGED_FILES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Building PanoptesInstaller.msi"
)

# Create a custom target for the installer
add_custom_target(installer ALL
    DEPENDS ${OUTPUT_DIR}/PanoptesInstaller.msi
)
add_dependencies(installer ${PACKAGED_TARGETS})
