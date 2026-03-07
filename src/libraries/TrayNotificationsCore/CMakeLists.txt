cmake_minimum_required(VERSION 3.15)
project(TrayNotificationsCore CXX)

set(SOURCES
    src/TrayNotifications.cpp
    src/TrayNotifications.rc
    assets/panoptes-head.ico
)

set(HEADERS
    include/TrayNotifications.h
    include/resource.h
)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

target_include_directories(${PROJECT_NAME}
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${PANOPTES_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)

if(MSVC)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
    )
endif()

install(TARGETS ${PROJECT_NAME}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

file(GLOB PUBLIC_HEADERS "*.h")
install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
) 