cmake_minimum_required(VERSION 3.23)
project(SignumPAdESPrototype LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(PoDoFo 1.0.0 REQUIRED)

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
