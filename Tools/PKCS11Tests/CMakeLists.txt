cmake_minimum_required(VERSION 3.23)
project(SignumPKCS11OfflineTests LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
if(NOT APPLE)
    message(FATAL_ERROR "Signum provider tests target macOS")
endif()
find_package(Threads REQUIRED)
add_library(signum-pkcs11-mock MODULE mock_provider.c asan_image_teardown.c)
target_include_directories(signum-pkcs11-mock PRIVATE ../../Sources/CPKCS11)
target_link_libraries(signum-pkcs11-mock PRIVATE Threads::Threads)
add_executable(signum-pkcs11-tests lifecycle_tests.cpp ../../Sources/CPKCS11/pkcs11_shim.c)
target_include_directories(signum-pkcs11-tests PRIVATE ../../Sources/CPKCS11 ../../Sources/CPKCS11/include)
target_link_libraries(signum-pkcs11-tests PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(signum-pkcs11-tests PRIVATE -Wall -Wextra)
enable_testing()
add_test(NAME signum-provider-lifecycle COMMAND signum-pkcs11-tests $<TARGET_FILE:signum-pkcs11-mock>)
set_tests_properties(signum-provider-lifecycle PROPERTIES TIMEOUT 60)

# Separate from the product shim: balanced loader handles, live ASAN redzones,
# their retirement, actual unload and subsequent serial/concurrent reloads.
add_executable(signum-loader-contract-tests loader_contract_tests.cpp)
target_include_directories(signum-loader-contract-tests PRIVATE ../../Sources/CPKCS11)
target_link_libraries(signum-loader-contract-tests PRIVATE Threads::Threads ${CMAKE_DL_LIBS})
target_compile_options(signum-loader-contract-tests PRIVATE -Wall -Wextra)
add_test(NAME signum-loader-contracts COMMAND signum-loader-contract-tests $<TARGET_FILE:signum-pkcs11-mock>)
set_tests_properties(signum-loader-contracts PROPERTIES TIMEOUT 60)

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/mock-provider-path.txt" CONTENT "$<TARGET_FILE:signum-pkcs11-mock>")

# Shared SignumCore certificate policy, also enforced by native signing entry points.
target_sources(signum-pkcs11-tests PRIVATE ../../Sources/CCertificatePolicy/certificate_policy.c)
target_include_directories(signum-pkcs11-tests PRIVATE ../../Sources/CCertificatePolicy/include)
target_link_libraries(signum-pkcs11-tests PRIVATE "-framework Security" "-framework CoreFoundation")
