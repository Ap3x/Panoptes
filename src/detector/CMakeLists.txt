# Builds PanoptesDetector.exe with Go into bin/<config>, next to the service that starts it, and
# copies the rules to bin/<config>/rules.
#
# The protobuf code in src/pb is checked in, so building needs only Go. After changing
# proto/src/panoptes.proto, regenerate it with `go generate ./...` (see README.md).
find_program(GO_EXECUTABLE go
    HINTS "$ENV{ProgramFiles}/Go/bin" "$ENV{GOROOT}/bin"
    DOC "Go toolchain used to build PanoptesDetector")
if(NOT GO_EXECUTABLE)
    message(FATAL_ERROR "BUILD_DETECTOR needs Go (https://go.dev/dl, or winget install GoLang.Go). Turn BUILD_DETECTOR off to build without the detector.")
endif()

set(DETECTOR_OUT_DIR "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>")
file(GLOB_RECURSE DETECTOR_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.go"
    "${CMAKE_CURRENT_SOURCE_DIR}/go.mod"
    "${CMAKE_CURRENT_SOURCE_DIR}/go.sum")
file(GLOB DETECTOR_RULES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/rules/*.yaml")

# Always runs; go build is incremental, so an unchanged detector costs about a second. The rules
# folder is recreated so a deleted rule does not linger in the build or the package
add_custom_target(PanoptesDetector ALL
    COMMAND "${GO_EXECUTABLE}" build -trimpath -o "${DETECTOR_OUT_DIR}/PanoptesDetector.exe" ./src
    COMMAND "${CMAKE_COMMAND}" -E rm -rf "${DETECTOR_OUT_DIR}/rules"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${DETECTOR_OUT_DIR}/rules"
    COMMAND "${CMAKE_COMMAND}" -E copy ${DETECTOR_RULES} "${DETECTOR_OUT_DIR}/rules"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    SOURCES ${DETECTOR_SOURCES} ${DETECTOR_RULES}
    COMMENT "Building PanoptesDetector (Go)"
    VERBATIM
)
