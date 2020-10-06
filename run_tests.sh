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
make

echo "Running tests..."

./tests
