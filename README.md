# TurboJAM

TurboJAM is a C++ implementation of the [JAM paper](https://github.com/gavofyork/graypaper) by Gavin Wood.

## Build Instructions

The code is regularly tested in the following build environments for the x86-64 architecture:
- Microsoft Visual C++ (included with Visual Studio Community 2022 on Windows)
- Clang 18 on Ubuntu 24.04
- GCC 13 on Ubuntu 24.04

If you encounter compilation issues in a different environment,
please check whether the issue also occurs in one of the supported environments above.
When reporting a problem, include details about your build setup to help with troubleshooting.

### Ubuntu Linux 24.04 LTS
1. Clone the repository including all submodules:
   ```
   git clone --recursice https://github.com/r2rationality/turbojam.git
   cd turbojam
   ```
3. Install the necessary packages:
   ```
   sudo apt update
   sudo apt install -y ninja-build cmake build-essential curl libboost-all-dev libfmt-dev libsodium-dev libssl-dev pkgconf
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   . $HOME/.cargo/env
   ```
4. Configure the build with CMake
   ```
   cmake -B build-gcc-rel -G Ninja
   ```
5. Prepare the binaries:
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
The project uses the following test-vector sets and tools to verify its conformance:
- [W3F Test Vectors](https://github.com/w3f/jamtestvectors)
- [Test Vectors by Davide Galassi](https://github.com/davxy/jam-test-vectors/)
- [PVM Test Vectors by Jan Bujak](https://github.com/koute/jamtestvectors/tree/master_pvm_initial)
- [PolkaJam binary releases](https://github.com/paritytech/polkajam-releases)

## Protocol documentation
- [JAM paper](https://github.com/gavofyork/graypaper)
- [JAM Simple Networking Protocol](https://github.com/zdave-parity/jam-np/blob/main/simple.md)
- [JIP-1: Debug message host call](https://hackmd.io/@polkadot/jip1)
- [JIP-2: Node RPC](https://hackmd.io/@polkadot/jip2)
- [JIP-3: Structured Logging](https://hackmd.io/@polkadot/jip3)
- [JIP-4 Chainspec file](https://github.com/polkadot-fellows/JIPs/pull/1)
- [JIP-5: Secret key derivation](https://github.com/polkadot-fellows/JIPs/pull/2)
- [JIP-6: Program metadata](https://github.com/polkadot-fellows/JIPs/pull/3)
- [JAM community-generated documentation](https://docs.jamcha.in/)

## Account IDs
- DOT: 14Gnp9cpb4mrXrpbCVNQSEPyL3QhoccGB9qpTRxqKWWMWSxn
- KSM: Fr7L8hdMeXJqydX1Z8TC2vpd1hHuysJZ2x5goFSFDhL5Ay8
