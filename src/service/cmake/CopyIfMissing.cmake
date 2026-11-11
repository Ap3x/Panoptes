# Copies SRC to DST only when DST does not exist yet, so local edits to DST survive rebuilds.
# Usage: cmake -DSRC=<file> -DDST=<file> -P CopyIfMissing.cmake
if(NOT EXISTS "${DST}")
    file(COPY_FILE "${SRC}" "${DST}")
    message(STATUS "Copied ${SRC} to ${DST}")
endif()
