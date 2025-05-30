find_program(CARGO cargo REQUIRED)

add_library(ark_vrf_cpp STATIC IMPORTED)
target_include_directories(ark_vrf_cpp INTERFACE ark-vrf-cpp/include)
if (MSVC)
    set(ARK_VRF_CPP_PATH "${CMAKE_CURRENT_LIST_DIR}/ark-vrf-cpp/target/release/ark_vrf_cpp.lib")
else()
    set(ARK_VRF_CPP_PATH "${CMAKE_CURRENT_LIST_DIR}/ark-vrf-cpp/target/release/libark_vrf_cpp.a")
endif()
add_custom_target(
    ark_vrf_cpp_lib ${CARGO} build --release
    BYPRODUCTS ${ARK_VRF_CPP_PATH}
    WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/ark-vrf-cpp"
)
add_dependencies(ark_vrf_cpp DEPENDS ark_vrf_cpp_lib)
set_target_properties(ark_vrf_cpp PROPERTIES IMPORTED_LOCATION ${ARK_VRF_CPP_PATH})

add_library(3rdparty OBJECT hash-library/keccak.cpp nanobench.cpp)
target_include_directories(3rdparty PUBLIC .)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(3rdparty PUBLIC ark_vrf_cpp)

include(ExternalProject)
ExternalProject_Add(
    msquic_build
    SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/msquic"
    BINARY_DIR "${CMAKE_CURRENT_LIST_DIR}/msquic/bld"
    INSTALL_DIR "${CMAKE_CURRENT_LIST_DIR}/msquic/build"
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DQUIC_BUILD_SHARED=OFF
    BUILD_ALWAYS 1
)

add_dependencies(3rdparty msquic_build)
target_include_directories(3rdparty PUBLIC msquic/build/include)
target_link_directories(3rdparty PUBLIC msquic/build/lib)
target_link_libraries(3rdparty PUBLIC msquic)

if(UNIX)
    target_link_libraries(3rdparty PUBLIC numa)
endif()
if (MSVC)
    target_link_libraries(ark_vrf_cpp INTERFACE bcrypt.lib advapi32.lib kernel32.lib advapi32.lib ntdll.lib userenv.lib ws2_32.lib dbghelp.lib)
endif()
