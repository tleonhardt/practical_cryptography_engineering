Building on Windows
===================

On Windows, CMake generates a Visual Studio solution for either x86 or x64 (not both).  So in general you have to
create two separate build folders.

Here, we have only included an x64 static libsodium library, so we will build for that.

Build requires CMake and Visual Studio 2015

Use the following sequence of commands to build on Windows:

```bash
mkdir build64 & pushd build64
cmake -G "Visual Studio 14 2015 Win64" ..
popd
cmake --build build64 --config Release
```

This will generate the executables in the build64\Release folder.

Building on Linux or macOS
==========================
```bash
mkdir build; pushd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

This will generate the executables in the build directory.
