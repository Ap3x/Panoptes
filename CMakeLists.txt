cmake_minimum_required (VERSION 3.13)

set(CMAKE_C_COMPILER "cl.exe")
set(CMAKE_CXX_COMPILER "cl.exe")

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("Panoptes-Full" VERSION 1.0.0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

add_executable(PanoptesService)
add_library(Panoptes-DLL SHARED)

add_subdirectory("Panoptes-DLL")
add_subdirectory("Panoptes-Agent")
add_subdirectory("Panoptes-Driver")

#CPack

set(CPACK_PACKAGE_NAME "Panoptes EDR")
set(CPACK_PACKAGE_VERSION "0.9.0")
set(CPACK_PACKAGE_VENDOR "Ap3x")
set(CPACK_PACKAGE_CONTACT "https://github.com/Ap3x")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The Panoptes EDR")
set(CPACK_WIX_PRODUCT_ICON "${CMAKE_CURRENT_SOURCE_DIR}/assets/installicon.ico")
#set(CPACK_PACKAGE_ICON "${CMAKE_CURRENT_SOURCE_DIR}/assets/installicon.ico")
set(CPACK_WIX_UI_DIALOG "${CMAKE_CURRENT_SOURCE_DIR}/assets/dialog.bmp")
set(CPACK_WIX_UI_BANNER "${CMAKE_CURRENT_SOURCE_DIR}/assets/banner.bmp")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt")
# Set package upgrade code (generate GUID using guidgen on Windows)
set(CPACK_WIX_UPGRADE_GUID "8C0A76F1-2618-4908-B99C-6142E5EFAAF3")
set(CPACK_PACKAGE_DIRECTORY  "${CMAKE_CURRENT_SOURCE_DIR}/bin/packages")

install(TARGETS Panoptes-DLL DESTINATION .)
install(TARGETS PanoptesService DESTINATION .)
install(TARGETS PanoptesDriver DESTINATION drivers)

# Include CPack
include(CPack)

add_custom_target(PackageWIX
    COMMAND ${CMAKE_CPACK_COMMAND} -G WIX
    DEPENDS ${CMAKE_PROJECT_NAME}
    COMMENT "Packaging ${CMAKE_PROJECT_NAME} using WIX"
    VERBATIM
)
