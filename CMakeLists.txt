cmake_minimum_required(VERSION 3.16)

project(MonocypherCpp)


set(CMAKE_CXX_STANDARD 17)

include_directories(
    "include"
)


add_library( MonocypherCpp STATIC
    src/Monocypher.cc
    src/Monocypher-ed25519.cc
    src/Monocypher+sha256.cc
    src/Monocypher+xsalsa20.cc
)


#### TESTS

add_executable( MonocypherCppTests
    test/tests.cc
)

target_link_libraries( MonocypherCppTests PRIVATE
    MonocypherCpp
)

install(TARGETS MonocypherCppTests)

enable_testing()

add_test(
    NAME MonocypherCppTests
    COMMAND MonocypherCppTests
)
