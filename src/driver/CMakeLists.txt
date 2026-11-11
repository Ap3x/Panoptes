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
    src/ioctl.cpp
    src/trace.cpp
    src/event_queue.cpp
    src/inject_exclusions.cpp
)

# Define header files
set(HEADER_FILES
    include/driver_constants.h
    include/pano_events.h
    include/pano_filter.h
    include/ioctl.h
    include/shellcode.h
    include/structs.h
    include/trace.h
    include/callbacks.h
    include/event_queue.h
    include/inject_exclusions.h
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

# Output to bin/<config>/driver alongside the rest of the build output
set(DRIVER_OUTPUT_DIR "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/driver")

set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${DRIVER_OUTPUT_DIR}"
)

target_link_libraries(${PROJECT_NAME} WDK::FLTMGR WDK::WDMSEC)

# Set entry point for the driver
set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "/ENTRY:DriverEntry /INTEGRITYCHECK")

# Copy INF file to output directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
    ${CMAKE_CURRENT_SOURCE_DIR}/driver-files/Panoptes.inf
    ${DRIVER_OUTPUT_DIR}/Panoptes.inf
    COMMENT "Copying INF file to output directory"
)

# Run Inf2Cat to create catalog file
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND "${x86_BUILD_TOOLS_PATH}Inf2Cat.exe" /driver:${DRIVER_OUTPUT_DIR} /os:10_x64 /verbose
    WORKING_DIRECTORY "${DRIVER_OUTPUT_DIR}"
    COMMENT "Running Inf2Cat to create catalog file"
)

# Sign with the Panoptes test certificate (created on first use, then reused) and export
# that same certificate as Panoptes.cer. package-target.ps1 signs the hook DLLs with it too
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
    -File "${CMAKE_CURRENT_SOURCE_DIR}/sign-panoptes.ps1"
    -ToolsDir "${x64_BUILD_TOOLS_PATH}"
    -Files "${DRIVER_OUTPUT_DIR}/Panoptes.sys"
    -ExportCer "${DRIVER_OUTPUT_DIR}/Panoptes.cer"
  COMMENT "Signing the driver"
  VERBATIM
)

# add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
#   COMMAND "${x64_BUILD_TOOLS_PATH}/certmgr.exe" -del -all -s PanoptesCertStore
#   COMMENT "Deleting Certificate"
# )