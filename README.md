# FreshRDI
A fresh implementation of shellcode reflective DLL injection using
[Assembly Line](https://github.com/robleh/assemblyline).

## Requirements
- MSVC or Clang toolchain
- CMake 3.26
- Ninja
- Windows SDK

## Build 🏗️
### Command Line
```console
cmake.exe --build --preset windows-x64-msvc-release
```

### Visual Studio
- Open the project as a folder.
- Select a build preset
- `Build -> Build All`

## Test 🧪
Once the project has been built, all of the registered tests can be run.

### Command Line
```console
ctest.exe --preset windows-x64-msvc-release
```

### Visual Studio
- Open the project as a folder.
- Select your build preset in the drop down menu.
- Open the `Test Explorer`
- `Build -> Build All`
