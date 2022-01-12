cmake_minimum_required(VERSION 3.16)

project(MonocypherCppTest)

add_executable( tests
    src/Monocypher.cc
    src/Monocypher-ed25519.cc
    test/tests.cc
)

include_directories(
    "include"
    "vendor/monocypher/src"
)

set_property(TARGET tests  
    PROPERTY CXX_STANDARD 17
)

install(TARGETS tests)

enable_testing()

add_test(
    NAME tests
    COMMAND tests
)
