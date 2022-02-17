cmake_minimum_required(VERSION 3.16)

project(MonocypherCpp)


set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD            11)
set(CMAKE_C_STANDARD_REQUIRED   ON)

if (MSVC)
    add_compile_options(/W4) # TODO: Add /WX
else()
    add_compile_options(-Wall -Wpedantic -Werror)
endif()

include_directories(
    "include/"
)


add_library( MonocypherCpp STATIC
    src/Monocypher.cc
    src/Monocypher-ed25519.cc
    src/Monocypher+sha256.cc
    src/Monocypher+xsalsa20.cc
)

if (NOT MSVC)
    set_source_files_properties(
        src/Monocypher+xsalsa20.cc  PROPERTIES COMPILE_OPTIONS  "-Wno-sign-compare"
    )
endif()

#### TESTS

add_executable( MonocypherCppTests
    tests/MonocypherCppTests.cc
    tests/tests_main.cc
)

target_include_directories( MonocypherCppTests PRIVATE
    "vendor/catch2/"
)

target_link_libraries( MonocypherCppTests PRIVATE
    MonocypherCpp
)
