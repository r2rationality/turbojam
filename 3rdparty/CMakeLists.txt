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
set(MSQUIC_INST  "${CMAKE_CURRENT_BINARY_DIR}/msquic-install") # you used this path already
set(MSQUIC_LIB   "${MSQUIC_INST}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}msquic${CMAKE_STATIC_LIBRARY_SUFFIX}")

include(ExternalProject)
ExternalProject_Add(
    msquic_build
    SOURCE_DIR  "${MSQUIC_SRC}"
    BINARY_DIR  "${MSQUIC_BUILD}"
    INSTALL_DIR "${MSQUIC_INST}"
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DQUIC_BUILD_SHARED=OFF
    UPDATE_DISCONNECTED
    STEP_TARGETS build install
    BUILD_BYPRODUCTS "${MSQUIC_LIB}"
)

add_library(msquic STATIC IMPORTED GLOBAL)
file(MAKE_DIRECTORY "${MSQUIC_INST}/include")
set_target_properties(msquic PROPERTIES
    IMPORTED_LOCATION "${MSQUIC_LIB}"
    INTERFACE_INCLUDE_DIRECTORIES "${MSQUIC_INST}/include"
)
add_dependencies(msquic msquic_build-install)

add_library(3rdparty OBJECT hash-library/keccak.cpp)
target_include_directories(3rdparty PUBLIC .)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(3rdparty PUBLIC ark_vrf_cpp erasure_coding ed25519_consensus_cpp msquic)

if(UNIX)
    target_link_libraries(3rdparty PUBLIC numa)
endif()

add_library(nanobench OBJECT nanobench.cpp)
