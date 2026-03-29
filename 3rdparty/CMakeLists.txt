function(add_cargo_staticlib TARGET_NAME CRATE_DIR LIB_BASENAME)
    set(CARGO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-${TARGET_NAME}")
    if (MSVC)
        set(LIB_PATH "${CARGO_OUT_DIR}/release/${LIB_BASENAME}.lib")
    else()
        set(LIB_PATH "${CARGO_OUT_DIR}/release/lib${LIB_BASENAME}.a")
    endif()

    set(CRATE_TOML "${CRATE_DIR}/Cargo.toml")
    set(CRATE_LOCK "${CRATE_DIR}/Cargo.lock")
    file(GLOB_RECURSE CRATE_SRC CONFIGURE_DEPENDS "${CRATE_DIR}/src/*.rs" "${CRATE_DIR}/build.rs")

    add_custom_command(
        OUTPUT "${LIB_PATH}"
        COMMAND "${CARGO}" build --release --target-dir ${CARGO_OUT_DIR}
        WORKING_DIRECTORY "${CRATE_DIR}"
        DEPENDS "${CRATE_TOML}" "${CRATE_LOCK}" ${CRATE_SRC}
        VERBATIM
        USES_TERMINAL
    )

    add_custom_target(${TARGET_NAME}_build DEPENDS "${LIB_PATH}")

    add_library(${TARGET_NAME} STATIC IMPORTED GLOBAL)
    set_target_properties(${TARGET_NAME} PROPERTIES
        IMPORTED_LOCATION "${LIB_PATH}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRATE_DIR}/include"
    )
    add_dependencies(${TARGET_NAME} ${TARGET_NAME}_build)
endfunction()

find_program(CARGO cargo REQUIRED)

add_cargo_staticlib(erasure_coding "${CMAKE_CURRENT_LIST_DIR}/erasure-coding" "erasure_coding")
add_cargo_staticlib(ark_vrf_cpp  "${CMAKE_CURRENT_LIST_DIR}/ark-vrf-cpp" "ark_vrf_cpp")
if (MSVC)
    target_link_libraries(ark_vrf_cpp INTERFACE bcrypt advapi32 kernel32 advapi32 ntdll userenv ws2_32 dbghelp)
endif()
add_cargo_staticlib(ed25519_consensus_cpp "${CMAKE_CURRENT_LIST_DIR}/ed25519-consensus-cpp" "ed25519_consensus_cpp")

set(MSQUIC_SRC   "${CMAKE_CURRENT_LIST_DIR}/msquic")
set(MSQUIC_BUILD "${CMAKE_CURRENT_BINARY_DIR}/msquic")
set(MSQUIC_PACKAGED_LIB "${MSQUIC_BUILD}/bin/Release/${CMAKE_STATIC_LIBRARY_PREFIX}msquic${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(MSQUIC_STATIC_LIB   "${MSQUIC_BUILD}/obj/Release/${CMAKE_STATIC_LIBRARY_PREFIX}msquic_static${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(MSQUIC_CORE_LIB     "${MSQUIC_BUILD}/obj/Release/${CMAKE_STATIC_LIBRARY_PREFIX}core${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(MSQUIC_PLATFORM_LIB "${MSQUIC_BUILD}/obj/Release/${CMAKE_STATIC_LIBRARY_PREFIX}msquic_platform${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(MSQUIC_BUILD_TARGETS msquic_lib)
set(MSQUIC_BYPRODUCTS "${MSQUIC_PACKAGED_LIB}")

if (WIN32)
    set(MSQUIC_ETW_HEADER "${MSQUIC_BUILD}/inc/MsQuicEtw.h")
    set(MSQUIC_BUILD_TARGETS msquic_static MsQuicEtw_HeaderBuild)
    set(MSQUIC_BYPRODUCTS
        "${MSQUIC_STATIC_LIB}"
        "${MSQUIC_CORE_LIB}"
        "${MSQUIC_PLATFORM_LIB}"
        "${MSQUIC_ETW_HEADER}"
    )
endif()

include(ExternalProject)
ExternalProject_Add(
    msquic_build
    SOURCE_DIR  "${MSQUIC_SRC}"
    BINARY_DIR  "${MSQUIC_BUILD}"
    CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DQUIC_BUILD_SHARED=OFF
        -DQUIC_SOURCE_LINK=OFF
        -DQUIC_EMBED_GIT_HASH=OFF
        -DQUIC_PDBALTPATH=OFF
    UPDATE_DISCONNECTED
    BUILD_COMMAND "${CMAKE_COMMAND}" --build <BINARY_DIR> --config Release --target ${MSQUIC_BUILD_TARGETS}
    STEP_TARGETS build
    BUILD_BYPRODUCTS
        ${MSQUIC_BYPRODUCTS}
    INSTALL_COMMAND ""
)

file(MAKE_DIRECTORY "${MSQUIC_BUILD}/inc")
if (WIN32)
    add_library(msquic INTERFACE)
    target_compile_definitions(msquic INTERFACE QUIC_BUILD_STATIC)
    target_include_directories(msquic INTERFACE "${MSQUIC_SRC}/src/inc" "${MSQUIC_BUILD}/inc")
    target_link_libraries(msquic INTERFACE
        "${MSQUIC_STATIC_LIB}"
        "${MSQUIC_CORE_LIB}"
        "${MSQUIC_PLATFORM_LIB}"
    )
    target_link_libraries(msquic INTERFACE
        ws2_32
        schannel
        ntdll
        bcrypt
        ncrypt
        crypt32
        iphlpapi
        advapi32
        wbemuuid
        winmm
        secur32
        onecore
    )
else()
    add_library(msquic STATIC IMPORTED GLOBAL)
    set_target_properties(msquic PROPERTIES
        IMPORTED_LOCATION "${MSQUIC_PACKAGED_LIB}"
        INTERFACE_INCLUDE_DIRECTORIES "${MSQUIC_SRC}/src/inc"
    )
endif()
add_dependencies(msquic msquic_build-build)

add_library(3rdparty OBJECT hash-library/keccak.cpp)
target_include_directories(3rdparty PUBLIC .)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(3rdparty PUBLIC ark_vrf_cpp erasure_coding ed25519_consensus_cpp msquic)

if(UNIX)
    target_link_libraries(3rdparty PUBLIC numa)
endif()

add_library(nanobench OBJECT nanobench.cpp)
