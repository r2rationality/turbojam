# TurboJAM

TurboJAM is a C++ implementation of the [JAM paper](https://github.com/gavofyork/graypaper) by Gavin Wood.

## Build Instructions

The code is regularly tested in the following build environments:
- The latest Visual C++ on Windows.
- Clang 18 that comes with Ubuntu Linux 24.04.
- GCC 13 that comes with Ubuntu Linux 24.04.
- Clang 17 installed with Homebrew on Mac OS.

### Ubuntu Linux 24.04 LTS
1. Configure the build with CMake
   ```
   cmake -B build-gcc-rel -G Ninja
   ```
2. Prepare the binaries:
   ```
   cmake --build build-gcc-rel -j -t all
   ```

### Windows / Visual C++
1. Set up the necessary Visual Studio environment variables for a command line build
    ```
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
   ```
2. Use vcpkg to install the required packages specified in vcpkg.json
   ```
    vcpkg install
   ```
3. Configure the build with CMake
   ```
   cmake -B build-win-rel -G Ninja -DCMAKE_BUILD_TYPE=Release --toolchain="%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
   ```
4. Prepare the binaries:
   ```
   cmake --build build-win-rel --config Release -j -t all
   ```

## Test Vectors
The project uses the following test-vector sets to verify its conformance:
- [W3F Test Vectors](https://github.com/w3f/jamtestvectors)
- [Test Vectors by Davide Galassi](https://github.com/davxy/jam-test-vectors/tree/polkajam-vectors)

## Account IDs
- DOT: 14Gnp9cpb4mrXrpbCVNQSEPyL3QhoccGB9qpTRxqKWWMWSxn
- KSM: Fr7L8hdMeXJqydX1Z8TC2vpd1hHuysJZ2x5goFSFDhL5Ay8
