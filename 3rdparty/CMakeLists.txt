add_library(ark_vrf_cpp STATIC IMPORTED)
target_include_directories(ark_vrf_cpp INTERFACE ark-vrf-cpp/include)
set_target_properties(ark_vrf_cpp PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_LIST_DIR}/ark-vrf-cpp/target/release/ark_vrf_cpp.lib")

add_library(3rdparty OBJECT hash-library/keccak.cpp nanobench.cpp)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(3rdparty PUBLIC .)
target_link_libraries(3rdparty PUBLIC ark_vrf_cpp)
target_link_libraries(ark_vrf_cpp INTERFACE bcrypt.lib advapi32.lib kernel32.lib advapi32.lib ntdll.lib userenv.lib ws2_32.lib dbghelp.lib)
