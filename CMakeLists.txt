cmake_minimum_required(VERSION 3.16)
project(vergeauth VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEVENT REQUIRED IMPORTED_TARGET libevent>=2.1)

add_library(llhttp STATIC
    third_party/llhttp/src/api.c
    third_party/llhttp/src/http.c
    third_party/llhttp/src/llhttp.c)
target_include_directories(llhttp PUBLIC third_party/llhttp/include)

add_executable(vergeauth src/main.c src/config.c src/http.c src/proxy.c)
target_compile_definitions(vergeauth PRIVATE _POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
target_compile_options(vergeauth PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
target_link_libraries(vergeauth PRIVATE llhttp PkgConfig::LIBEVENT)

option(VERGEAUTH_SANITIZE "Enable address and undefined behavior sanitizers" OFF)
if(VERGEAUTH_SANITIZE)
    foreach(target vergeauth llhttp)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    endforeach()
    target_link_options(vergeauth PRIVATE -fsanitize=address,undefined)
endif()

include(GNUInstallDirs)
install(TARGETS vergeauth RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
include(CTest)
if(BUILD_TESTING)
    add_executable(protocol_tests tests/protocol.c src/config.c src/http.c)
    target_compile_definitions(protocol_tests PRIVATE _POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700)
    target_compile_options(protocol_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    target_link_libraries(protocol_tests PRIVATE llhttp PkgConfig::LIBEVENT)
    if(VERGEAUTH_SANITIZE)
        target_compile_options(protocol_tests PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(protocol_tests PRIVATE -fsanitize=address,undefined)
    endif()
    add_test(NAME protocol COMMAND protocol_tests)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME cli COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.py $<TARGET_FILE:vergeauth>)
    add_test(NAME integration COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.py $<TARGET_FILE:vergeauth>)
    set_tests_properties(integration PROPERTIES TIMEOUT 90 SKIP_RETURN_CODE 77)
endif()
