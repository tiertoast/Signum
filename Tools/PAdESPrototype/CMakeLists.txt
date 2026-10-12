cmake_minimum_required(VERSION 3.23)
project(SignumPAdESPrototype LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# PoDoFo 1.1.x exports "podofo-config.cmake" and the target podofo::podofo.
# Do not request 1.0 compatibility: Homebrew's 1.1.2 config rejects it.
find_package(podofo CONFIG REQUIRED)
if(NOT TARGET podofo::podofo)
    message(FATAL_ERROR "Installed PoDoFo does not export podofo::podofo")
endif()

add_executable(signum-pades-local
    signum_pades_local.cpp
    ../../Sources/CPKCS11/pkcs11_shim.c
)
target_include_directories(signum-pades-local PRIVATE
    ../../Sources/CPKCS11/include
    ../../Sources/CPKCS11
)
target_link_libraries(signum-pades-local PRIVATE podofo::podofo ${CMAKE_DL_LIBS})
if(APPLE)
  target_link_libraries(signum-pades-local PRIVATE "-framework Security")
endif()
