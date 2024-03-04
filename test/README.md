**This is a RACE Plugin Repository**

**Plugin type:** Comms
**Performer:** TwoSix Labs
**Variation:** Python

## Build

### Getting the Core shared library

This project depends on the [Core Plugin](ghcr.io/tst-race/race-images/race-core:latest) project. Eventually, the artifacts of this project will be imported via some artifact verisioning system. For now you can take the lo-fi approach of cloning the project and building locally directly next to this project. CMake will automatically copy the required files to this project so long as the Core project is in a directory named `race-core`.

### Build the shared library

The project uses CMake to generate build files. To generate build files and build the shared lib run:

```
cd build
cmake ../source
cmake --build . # or just run make
```

### Directory structure
The project follows the CMake guidelines of having `source` and `build` directories and adds `include`, `lib`, and `test` directories.

#### `source` directory

All project sournce code is stored here. Generally this will be .cpp, but internal headers may be stored here as well/

#### `build` directory

This is an empty directory that holds all the temporary CMake files and the output shared library (typically a .so). Do not add anything to this directory. The idea behind the build directory is that you can delete it and start over fresh.

#### `include` directory

All exported headers should be put in this directory. Internal headers should be placed in `source`.

#### `lib` directory

Stores all the external headers and libs from Core.
WARNING: this directory may change pending team consensus.

#### `test` directory

Stores all source code for the test application.

### Build and run the test application

The test application also uses CMake. This program links against the main project shared library, so build that first. To generate build files, build, and run the test app:

```
cd test/build
cmake ../source
cmake --build . # or just run make
./EXECUTABLE
```
