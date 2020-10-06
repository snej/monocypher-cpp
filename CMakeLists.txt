cmake_minimum_required(VERSION 3.16)

project(MonocypherCppTest)

add_executable(tests
    test/tests.cc
    vendor/monocypher/src/monocypher.c
    vendor/monocypher/src/optional/monocypher-ed25519.c)

include_directories(
    "include"
    "vendor/monocypher/src"
    "vendor/monocypher/src/optional")

set_property(TARGET tests  PROPERTY CXX_STANDARD 14)

install(TARGETS tests)

enable_testing()

add_test(NAME tests  COMMAND tests)
