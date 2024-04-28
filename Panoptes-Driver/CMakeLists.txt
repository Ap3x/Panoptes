wdk_add_driver(PanoptesDriver
    KMDF 1.15
    src/Panoptes-Driver.c
    #include/message.h
    #include/Panoptes-Driver.h
    )

target_include_directories(PanoptesDriver PUBLIC    
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

set_target_properties(PanoptesDriver PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    PDB_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    OUTPUT_NAME "Panoptes"
)