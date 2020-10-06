#! /bin/bash -e

if [ ! -d vendor/monocypher/src ]
then
    echo "vendor/monocypher is missing! (Try running 'git submodule update --init')"
    exit 1
fi

echo "Compiling..."

clang -x c++ -std=c++14 -stdlib=libc++ -Wall \
   -I include -I vendor/monocypher/src -I vendor/monocypher/src/optional \
   test/tests.cc \
   vendor/monocypher/src/*.c \
   vendor/monocypher/src/optional/*.c \
   -lc++ \
   -o tests

echo "Running tests..."

./tests
rm tests
