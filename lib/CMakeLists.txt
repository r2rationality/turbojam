set(Boost_NO_WARN_NEW_VERSIONS 1)
if (WIN32)
    find_package(Boost 1.83 REQUIRED COMPONENTS json url coroutine thread stacktrace_windbg)
elseif(APPLE)
    find_package(Boost 1.83 REQUIRED COMPONENTS json url coroutine thread stacktrace_noop)
else()
    find_package(Boost 1.83 REQUIRED COMPONENTS json url coroutine thread stacktrace_backtrace)
endif()

find_package(PkgConfig REQUIRED)
find_package(fmt REQUIRED)
find_package(msquic CONFIG REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium>=1.0.18)
file(GLOB_RECURSE LIB_SRCS *.cpp)
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.test\\.cpp$")
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.bench\\.cpp$")
list(FILTER LIB_SRCS EXCLUDE REGEX "\\.fuzz\\.cpp$")
add_library(lib OBJECT ${LIB_SRCS})
target_precompile_headers(lib PUBLIC ${LIB_HDRS})
target_include_directories(lib PUBLIC .)
target_link_libraries(lib PUBLIC
    fmt::fmt
    ${SODIUM_LIBRARIES}
    Boost::json Boost::coroutine Boost::url Boost::thread
    msquic
)
target_link_directories(lib PUBLIC ${SODIUM_LIBRARY_DIRS})

if (WIN32)
    target_compile_options(lib PUBLIC "-DBOOST_STACKTRACE_USE_WINDBG")
    target_compile_options(lib PUBLIC "-DBOOST_STACKTRACE_LINK")
    target_link_libraries(lib PUBLIC Boost::stacktrace_windbg)
elseif(APPLE)
    target_compile_options(lib PUBLIC "-DBOOST_STACKTRACE_USE_NOOP")
    target_compile_options(lib PUBLIC "-DBOOST_STACKTRACE_LINK")
    target_link_libraries(lib PUBLIC Boost::stacktrace_noop dl)
else()
    target_compile_options(lib PUBLIC "-DBOOST_STACKTRACE_USE_BACKTRACE")
    target_compile_options(lib PUBLIC "-DBOOST_STACKTRACE_LINK")
    target_link_libraries(lib PUBLIC Boost::stacktrace_backtrace dl)
endif()

