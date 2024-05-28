cmake_minimum_required(VERSION 3.16)

project(MonocypherCpp
        VERSION     1.2
        DESCRIPTION "C++ bindings for Monocypher crypto library, and more"
        LANGUAGES   C CXX
)

option(MONOCYPHER_ENABLE_BLAKE3 "Adds the Blake3 digest algorithm" ON)

if (MONOCYPHER_ENABLE_BLAKE3)
    add_subdirectory(vendor/BLAKE3/c)
endif()

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


#### MAIN LIBRARY


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

if (MONOCYPHER_ENABLE_BLAKE3)
    target_sources( MonocypherCpp PRIVATE
        src/Monocypher+blake3.cc
    )
    target_include_directories( MonocypherCpp PRIVATE
        vendor/BLAKE3/c/
    )
    target_link_libraries( MonocypherCpp INTERFACE
        blake3
    )
endif()


#### TESTS


add_executable( MonocypherCppTests
    tests/MonocypherCppTests.cc
    tests/tests_main.cc
)

if (MONOCYPHER_ENABLE_BLAKE3)
    target_sources( MonocypherCppTests PRIVATE
        tests/Test_Blake3.cc
    )
endif()

target_include_directories( MonocypherCppTests PRIVATE
    "vendor/catch2/"
)

target_link_libraries( MonocypherCppTests PRIVATE
    MonocypherCpp
)
