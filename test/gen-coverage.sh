set -e
TEST_NAME=$1
if [ -z "$TEST_NAME" ]; then
  TEST_NAME="*"
fi
OUT_DIR=$2
if [ -z "$OUT_DIR" ]; then
  OUT_DIR="tmp/coverage"
fi
test -d "$OUT_DIR" || mkdir -p "$OUT_DIR"
BUILD_DIR=$3
if [ -z "$BUILD_DIR" ]; then
  BUILD_DIR="build"
fi
export ASAN_OPTIONS="malloc_context_size=100:fast_unwind_on_malloc=0:fast_unwind_on_fatal=0"
"$BUILD_DIR/tjam-test" "$TEST_NAME"
# Use the same LLVM tools selected for this build by CMake.
PROFDATA_BIN=$(sed -n 's/^LLVM_PROFDATA:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt")
COV_BIN=$(sed -n 's/^LLVM_COV:[^=]*=//p' "$BUILD_DIR/CMakeCache.txt")
: "${PROFDATA_BIN:?Configure the build with CMAKE_BUILD_TYPE=Coverage first}"
: "${COV_BIN:?Configure the build with CMAKE_BUILD_TYPE=Coverage first}"
"$PROFDATA_BIN" merge -sparse default.profraw -o tjam-test.profdata
"$COV_BIN" show -show-branches=percent -ignore-filename-regex=lib/dt/cli -ignore-filename-regex=3rdparty/ -format=html -output-dir="$OUT_DIR" "$BUILD_DIR/tjam-test" -instr-profile=tjam-test.profdata
