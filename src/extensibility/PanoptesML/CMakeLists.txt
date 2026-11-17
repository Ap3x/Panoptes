cmake_minimum_required(VERSION 3.21)

# PanoptesML: an extensibility module that scores static PE files with an ONNX model.
#
# ONNX Runtime needs a newer protobuf than the gRPC the rest of Panoptes is pinned to, so this
# module has its own vcpkg manifest (vcpkg.json and vcpkg-configuration.json here) and is built
# as a separate sub-build with its own vcpkg_installed folder. The other components never see
# its packages. Configured from the main project (BUILD_ML=ON), this file only adds that
# sub-build; the sub-build configures this file again as the top-level project and builds the
# DLL.

# PROJECT_IS_TOP_LEVEL can't tell: before project() below it still holds the root project's
# value, so compare source directories instead
if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR AND NOT DEFINED PANOPTES_ML_SUBBUILD)
    # Not the sub-build yet: configured from the root CMakeLists.txt
    include(ExternalProject)
    ExternalProject_Add(PanoptesML
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
        BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/ml"
        CMAKE_GENERATOR "${CMAKE_GENERATOR}"
        CMAKE_GENERATOR_PLATFORM x64
        CMAKE_ARGS
            -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
            -DVCPKG_TARGET_TRIPLET=x64-windows-static
            -DVCPKG_MANIFEST_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DPANOPTES_ML_SUBBUILD=ON
            -DPANOPTES_ROOT=${CMAKE_SOURCE_DIR}
            -DPANOPTES_BIN_DIR=${CMAKE_SOURCE_DIR}/bin
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
        INSTALL_COMMAND ""
        BUILD_ALWAYS ON
    )

    # PanoptesMLQuery (tools/mlquery), a Go tool that scores files with the DLL for testing. Built
    # into bin/<config> so it finds ext\PanoptesML.dll next to it
    find_program(GO_EXECUTABLE go HINTS "$ENV{ProgramFiles}/Go/bin" "$ENV{GOROOT}/bin")
    if(GO_EXECUTABLE)
        file(GLOB MLQUERY_SOURCES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/mlquery/*.go"
            "${CMAKE_CURRENT_SOURCE_DIR}/tools/go.mod")
        add_custom_target(PanoptesMLQuery ALL
            COMMAND "${GO_EXECUTABLE}" build -trimpath -o "${CMAKE_SOURCE_DIR}/bin/$<CONFIG>/PanoptesMLQuery.exe" ./mlquery
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tools"
            SOURCES ${MLQUERY_SOURCES}
            COMMENT "Building PanoptesMLQuery (Go)"
            VERBATIM
        )
        add_dependencies(PanoptesMLQuery PanoptesML)
    else()
        message(STATUS "PanoptesML: Go not found, so PanoptesMLQuery (tools/mlquery) is not built")
    endif()
    return()
endif()

project(PanoptesML LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Static CRT, like the other Panoptes binaries and the x64-windows-static triplet
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Also buildable on its own: cmake -S src/extensibility/PanoptesML -B build/ml with the vcpkg
# toolchain
if(NOT DEFINED PANOPTES_ROOT)
    get_filename_component(PANOPTES_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
endif()
if(NOT DEFINED PANOPTES_BIN_DIR)
    set(PANOPTES_BIN_DIR "${PANOPTES_ROOT}/bin")
endif()

find_package(onnxruntime CONFIG REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

add_library(PanoptesML SHARED
    src/dllmain.cpp
    src/pe_features.cpp
    src/ml_model.cpp
    src/model_seal.cpp
    src/service_client_ml.cpp
    include/PanoptesML.h
    ${PANOPTES_ROOT}/src/extensibility/core/ExtensibilityCore.h
    ${PANOPTES_ROOT}/proto/src/panoptes.proto
)

# The service's messages, generated with this sub-build's own protoc. The wire format is the
# same as the service's older protobuf, so the two talk without trouble
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${PROTO_BINARY_DIR}")
protobuf_generate(
    TARGET PanoptesML
    IMPORT_DIRS "${PANOPTES_ROOT}/proto/src"
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)
protobuf_generate(
    TARGET PanoptesML
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
    IMPORT_DIRS "${PANOPTES_ROOT}/proto/src"
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)

target_include_directories(PanoptesML PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PANOPTES_ROOT}/src/extensibility/core
    ${PROTO_BINARY_DIR}
)

target_compile_definitions(PanoptesML PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

if(MSVC)
    target_compile_options(PanoptesML PRIVATE /W3 /EHsc /MP)
endif()

target_link_libraries(PanoptesML PRIVATE
    onnxruntime::onnxruntime
    gRPC::grpc++
    protobuf::libprotobuf
    advapi32
    bcrypt
)

# protobuf declares its shared empty string, fixed_address_empty_string, as one of two types:
# GlobalEmptyStringConstexpr where std::string is constexpr-constructible (C++20, and on MSVC
# only without debug iterators, so Release), GlobalEmptyStringDynamicInit otherwise. vcpkg builds
# ONNX Runtime as C++20 and protobuf, onnx and gRPC as C++17, so in Release ONNX Runtime's
# libraries reference the Constexpr symbol while libprotobuf defines only the DynamicInit one
# (LNK2001). Both are one std::string at offset 0, so point the first at the second: ONNX Runtime
# then uses the same empty string, initialized by protobuf. Debug builds use DynamicInit
# throughout, and an alternate name nothing references is ignored
target_link_options(PanoptesML PRIVATE
    "/ALTERNATENAME:?fixed_address_empty_string@internal@protobuf@google@@3VGlobalEmptyStringConstexpr@123@B=?fixed_address_empty_string@internal@protobuf@google@@3VGlobalEmptyStringDynamicInit@123@A"
)

# Straight into bin/<config>/ext, where the container loads modules from. The model is loaded
# from the same folder
set_target_properties(PanoptesML PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PANOPTES_BIN_DIR}/$<CONFIG>/ext"
    PDB_OUTPUT_DIRECTORY "${PANOPTES_BIN_DIR}/$<CONFIG>/ext"
)

# The model, when one is checked in (assets/ml/model.onnx). Without one the module loads but
# every scan fails with "cannot load model.onnx".
#
# By default it's built into the DLL, encrypted: tools/sealmodel (Go) encrypts it with AES-256-GCM
# under a new random key, the result is linked in as an RCDATA resource, and the key is compiled
# in from the generated model_key.h. The DLL decrypts it in memory (src/model_seal.cpp). With
# PANOPTES_ML_EMBED_MODEL off, model.onnx is copied next to the DLL instead, as plain ONNX
option(PANOPTES_ML_EMBED_MODEL "Encrypt assets/ml/model.onnx into PanoptesML.dll instead of shipping it next to it" ON)
set(PANOPTES_ML_MODEL "${PANOPTES_ROOT}/assets/ml/model.onnx")
if(EXISTS "${PANOPTES_ML_MODEL}" AND PANOPTES_ML_EMBED_MODEL)
    find_program(GO_EXECUTABLE go HINTS "$ENV{ProgramFiles}/Go/bin" "$ENV{GOROOT}/bin")
    if(NOT GO_EXECUTABLE)
        message(FATAL_ERROR "PanoptesML: Go is needed to encrypt the model into the DLL (tools/sealmodel). "
            "Install Go, or configure with -DPANOPTES_ML_EMBED_MODEL=OFF to ship model.onnx unencrypted")
    endif()
    set(MODEL_SEAL_DIR "${CMAKE_CURRENT_BINARY_DIR}/model")
    set(MODEL_SEALED "${MODEL_SEAL_DIR}/model.sealed")
    set(MODEL_KEY_HEADER "${MODEL_SEAL_DIR}/model_key.h")
    file(MAKE_DIRECTORY "${MODEL_SEAL_DIR}")
    file(GLOB SEALMODEL_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tools/sealmodel/*.go")
    # Sealed again (with a new key) only when the model or the tool changes
    add_custom_command(
        OUTPUT "${MODEL_SEALED}" "${MODEL_KEY_HEADER}"
        COMMAND "${GO_EXECUTABLE}" run ./sealmodel -in "${PANOPTES_ML_MODEL}" -out "${MODEL_SEALED}" -header "${MODEL_KEY_HEADER}"
        DEPENDS "${PANOPTES_ML_MODEL}" ${SEALMODEL_SOURCES}
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/tools"
        COMMENT "Encrypting assets/ml/model.onnx into PanoptesML.dll"
        VERBATIM
    )
    # rc.exe reads the sealed file; its path, with the backslashes escaped for the .rc string
    file(TO_NATIVE_PATH "${MODEL_SEALED}" MODEL_SEALED_NATIVE)
    string(REPLACE "\\" "\\\\" MODEL_SEALED_RC "${MODEL_SEALED_NATIVE}")
    file(CONFIGURE OUTPUT "${MODEL_SEAL_DIR}/model.rc"
        CONTENT "PANOML_MODEL RCDATA \"${MODEL_SEALED_RC}\"\n")
    target_sources(PanoptesML PRIVATE "${MODEL_SEAL_DIR}/model.rc" "${MODEL_SEALED}" "${MODEL_KEY_HEADER}")
    set_source_files_properties("${MODEL_SEAL_DIR}/model.rc" PROPERTIES OBJECT_DEPENDS "${MODEL_SEALED}")
    set_source_files_properties(src/model_seal.cpp PROPERTIES
        COMPILE_DEFINITIONS PANO_ML_EMBEDDED_MODEL
        OBJECT_DEPENDS "${MODEL_KEY_HEADER}")
    target_include_directories(PanoptesML PRIVATE "${MODEL_SEAL_DIR}")
    # A plain model.onnx from an earlier build would be packaged with the DLL; the embedded model
    # is used anyway, so remove it
    add_custom_command(TARGET PanoptesML POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rm -f "$<TARGET_FILE_DIR:PanoptesML>/model.onnx"
        COMMENT "Removing a plain model.onnx next to PanoptesML.dll (the model is embedded)")
elseif(EXISTS "${PANOPTES_ML_MODEL}")
    # A target of its own rather than a post-build step, so a changed model is copied even when
    # the DLL doesn't relink
    add_custom_target(PanoptesMLModel ALL
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${PANOPTES_ML_MODEL}" "$<TARGET_FILE_DIR:PanoptesML>/model.onnx"
        COMMENT "Copying the ML model next to PanoptesML.dll")
    add_dependencies(PanoptesMLModel PanoptesML)
else()
    message(STATUS "PanoptesML: no assets/ml/model.onnx; see src/extensibility/README.md")
endif()
