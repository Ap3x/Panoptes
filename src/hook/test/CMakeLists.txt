# Tests for the hook DLL of the architecture being built. The x64 tests are built by the main
# project and the x86 tests by the Win32 sub-build
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(HOOK_ARCH "x64")
else()
    set(HOOK_ARCH "x86")
endif()

# Test_PanoptesDLL checks the hooks are placed and removed. Each Test_<API> checks the
# detections of one hooked API (and its Ex variant, if any), using the shared
# hook_test_harness.hpp. The map and unmap tests also share hook_test_sections.hpp
set(HOOK_TESTS
    Test_PanoptesDLL
    Test_NtWriteVirtualMemory
    Test_NtProtectVirtualMemory
    Test_NtAllocateVirtualMemory
    Test_NtReadVirtualMemory
    Test_NtMapViewOfSection
    Test_NtUnmapViewOfSection
    Test_NtCreateThreadEx
    Test_NtQueueApcThread
    Test_NtSetInformationProcess
)

foreach(TEST ${HOOK_TESTS})
    set(TEST_NAME ${TEST}${HOOK_ARCH})

    add_executable(${TEST_NAME} ${TEST}.cpp hook_test_harness.hpp hook_test_sections.hpp)

    # Make sure the DLL is built before the test that loads it
    add_dependencies(${TEST_NAME} PanoptesDLL${HOOK_ARCH})

    set_target_properties(${TEST_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${PANOPTES_BIN_DIR}/$<CONFIG>/tests"
    )

    # The root project's TargetPackage depends on these, so the KDNET package includes them
    set_property(GLOBAL APPEND PROPERTY PANOPTES_HOOK_TEST_TARGETS ${TEST_NAME})
endforeach()
