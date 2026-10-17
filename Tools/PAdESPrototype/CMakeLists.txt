cmake_minimum_required(VERSION 3.23)
project(SignumPAdESPrototype LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# PoDoFo 1.1.x exports "podofo-config.cmake" and the target podofo::podofo.
# Do not request 1.0 compatibility: Homebrew's 1.1.2 config rejects it.
find_package(podofo 1.1.2 EXACT CONFIG REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
if(NOT APPLE)
    message(FATAL_ERROR "Signum PAdES reliability implementation requires macOS")
endif()
if(NOT TARGET podofo::podofo)
    message(FATAL_ERROR "Installed PoDoFo does not export podofo::podofo")
endif()

add_library(signum-pades-reliability STATIC TransactionalOutput.cpp PAdESVerification.cpp)
target_link_libraries(signum-pades-reliability PUBLIC OpenSSL::Crypto "-framework CoreGraphics" "-framework CoreFoundation")
target_include_directories(signum-pades-reliability PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(signum-pades-reliability PRIVATE -Wall -Wextra -Wpedantic)

add_executable(signum-pades-local
    signum_pades_local.cpp
    ../../Sources/CPKCS11/pkcs11_shim.c
)
target_include_directories(signum-pades-local PRIVATE
    ../../Sources/CPKCS11/include
    ../../Sources/CPKCS11
)
target_link_libraries(signum-pades-local PRIVATE podofo::podofo signum-pades-reliability ${CMAKE_DL_LIBS})
if(APPLE)
  target_link_libraries(signum-pades-local PRIVATE "-framework Security")
endif()

option(SIGNUM_BUILD_OFFLINE_TESTS "Build local synthetic PAdES tests" OFF)
if(SIGNUM_BUILD_OFFLINE_TESTS)
    enable_testing()
    add_executable(signum-pades-tests tests/reliability_tests.cpp)
    target_link_libraries(signum-pades-tests PRIVATE signum-pades-reliability podofo::podofo OpenSSL::Crypto)
    add_test(NAME signum-pades-reliability COMMAND signum-pades-tests)
    set_tests_properties(signum-pades-reliability PROPERTIES TIMEOUT 60)
endif()
