set -e
test -d /fuzzer || echo "/fuzzer volume must be mounted!"
sudo chown dev:dev /fuzzer
TURBO_LOG_PATH=/fuzzer/fuzzer.log /home/dev/turbojam/build/tjam fuzzer-api /fuzzer/fuzzer.sock