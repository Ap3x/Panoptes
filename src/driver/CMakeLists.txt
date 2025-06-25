cmake_minimum_required(VERSION 3.15)
project(PanoptesDriver)

# Include FindWDK module
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
find_package(WDK REQUIRED)

# Set C++ standard to match MSVC project (stdcpp17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Define source files
set(SOURCE_FILES
    src/callbacks.cpp
    src/driver.cpp
    src/pano_filter.cpp
    src/inject.cpp
    src/ioctl.cpp
    src/pano_query.cpp
    src/trace.cpp
)

# Define header files
set(HEADER_FILES
    include/driver_constants.h
    include/pano_filter.h
    include/inject.h
    include/ioctl.h
    include/pano_query.h
    include/shellcode.h
    include/structs.h
    include/trace.h
    include/callbacks.h
)

# Add the driver target
# https://learn.microsoft.com/en-us/windows/win32/winprog/using-the-windows-headers?redirectedfrom=MSDN
# https://github.com/MicrosoftDocs/windows-driver-docs/blob/staging/windows-driver-docs-pr/kernel/updating-deprecated-exallocatepool-calls.md
wdk_add_driver(${PROJECT_NAME} 
    KMDF 1.33
    WINVER 0x0A00
    NTDDI_VERSION 0x0A000008
    ${SOURCE_FILES}
    ${HEADER_FILES}
)

# Add include directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set target name to match MSVC project
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "Panoptes")

# Set output directory to match MSVC project structure
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/driver"
)

target_link_libraries(${PROJECT_NAME} WDK::FLTMGR)

# Set entry point for the driver
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/ENTRY:DriverEntry /INTEGRITYCHECK")

# Copy INF file to output directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_CURRENT_SOURCE_DIR}/driver-files/Panoptes.inf
    ${CMAKE_SOURCE_DIR}/bin/${PRESET_NAME}/driver/${CMAKE_BUILD_TYPE}/Panoptes.inf
    COMMENT "Copying INF file to output directory"
)

# Run Inf2Cat to create catalog file
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND "${x86_BUILD_TOOLS_PATH}Inf2Cat.exe" /driver:${CMAKE_SOURCE_DIR}/bin/driver/${CMAKE_BUILD_TYPE} /os:10_x64 /verbose
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/bin/driver/${CMAKE_BUILD_TYPE}"
    COMMENT "Running Inf2Cat to create catalog file"
)

# add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
#   COMMAND "${x64_BUILD_TOOLS_PATH}/makecert.exe" -r -pe -ss PanoptesCertStore -n "CN=Panoptes" "${CMAKE_SOURCE_DIR}/bin/driver/${CMAKE_BUILD_TYPE}/Panoptes.cer"
#   COMMENT "Generating a driver certificate"
#   AUTO
# )

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND "${x64_BUILD_TOOLS_PATH}/signtool.exe" sign /a /v /fd sha256 /s PanoptesCertStore /n "Panoptes" /t http://timestamp.digicert.com "${CMAKE_SOURCE_DIR}/bin/driver/${CMAKE_BUILD_TYPE}/Panoptes.sys"
  COMMENT "Signing the driver"
)

# add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
#   COMMAND "${x64_BUILD_TOOLS_PATH}/certmgr.exe" -del -all -s PanoptesCertStore
#   COMMENT "Deleting Certificate"
# )