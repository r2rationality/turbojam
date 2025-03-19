add_library(3rdparty OBJECT nanobench.cpp)
target_include_directories(3rdparty PUBLIC .)
set_target_properties(3rdparty PROPERTIES LINKER_LANGUAGE CXX)
