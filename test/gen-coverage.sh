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
"$BUILD_DIR/tjam-test" "$TEST_NAME"
if [ -f /usr/bin/llvm-profdata-19 ]; then
  PROFDATA_BIN=llvm-profdata-19
  COV_BIN=llvm-cov-19
else
  PROFDATA_BIN=llvm-profdata
  COV_BIN=llvm-cov
fi
"$PROFDATA_BIN" merge -sparse default.profraw -o tjam-test.profdata
"$COV_BIN" show -show-branches=percent -ignore-filename-regex=lib/dt/cli -ignore-filename-regex=3rdparty/ -format=html -output-dir="$OUT_DIR" "$BUILD_DIR/tjam-test" -instr-profile=tjam-test.profdata
