#! /bin/bash -e

if [ ! -d vendor/monocypher/src ]
then
    echo "vendor/monocypher is missing! (Try running 'git submodule update --init')"
    exit 1
fi

echo "Building..."

mkdir -p build_cmake
cd build_cmake
cmake ..
cmake --build .

echo "Running tests..."

if [ -e Debug/MonocypherCppTests.exe ]
then
    Debug/MonocypherCppTests.exe
else
    ./MonocypherCppTests
fi
