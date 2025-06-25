cmake_minimum_required(VERSION 4.0)  # Required for WiX v4 support
project(PanoptesInstaller)

find_program(WIX_COMMAND wix.exe
    PATHS "$ENV{USERPROFILE}/.dotnet/tools"
    DOC "Path to WiX v5 command-line tool")

if(NOT WIX_COMMAND)
    message(FATAL_ERROR "WiX v5 Toolset not found. Please install using: dotnet tool install --global wix --version 5.0.0")
endif()

# Set output directories
set(OUTPUT_DIR "${CMAKE_SOURCE_DIR}/bin/installer")
file(MAKE_DIRECTORY ${OUTPUT_DIR})

# Define WiX source files
set(WIX_SOURCES
    AppComponents.wxs
    Execute.wxs
    Folders.wxs
    Package.en-us.wxl
    Package.wxs
)

# Create custom command for WiX v5 build
add_custom_command(
    OUTPUT ${OUTPUT_DIR}/PanoptesInstaller.msi
    COMMAND ${WIX_COMMAND} build
        -arch x64
        -ext WixToolset.UI.wixext/5
        -ext WixToolset.Util.wixext/5
        -bindpath "${CMAKE_SOURCE_DIR}/assets/yara"
        -bindpath "${CMAKE_SOURCE_DIR}/assets"
        -bindpath "${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}"
        -bindpath "${CMAKE_SOURCE_DIR}/bin/driver/${CMAKE_BUILD_TYPE}"
        -bindpath "${CMAKE_SOURCE_DIR}/bin/driver"
        -bindpath "${CMAKE_SOURCE_DIR}/assets/icons"
        -bindpath "${CMAKE_CURRENT_SOURCE_DIR}/assets"
        ${WIX_SOURCES}
        -o ${OUTPUT_DIR}/PanoptesInstaller.msi
    DEPENDS ${WIX_SOURCES}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Create a custom target for the installer
add_custom_target(installer ALL
    DEPENDS ${OUTPUT_DIR}/PanoptesInstaller.msi
)

# Configure CPack with WiX v5
include(CPack)
set(CPACK_GENERATOR "WIX")
set(CPACK_WIX_VERSION "5")
set(CPACK_WIX_ARCHITECTURE "x64")
set(CPACK_WIX_UI_REF "WixUI_InstallDir")
set(CPACK_WIX_EXTENSIONS "WixToolset.UI.wixext;WixToolset.Util.wixext")
