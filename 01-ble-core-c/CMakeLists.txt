cmake_minimum_required(VERSION 3.16)
project(ble_core C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(BLE_SANITIZE "Build tests with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

set(BLE_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
                 -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Werror)

# The library: C99, no heap, no libc beyond freestanding headers.
add_library(ble_core STATIC
    src/ble_aes.c
    src/ble_rpa.c
    src/ble_ad.c
    src/ble_hci.c)
target_include_directories(ble_core PUBLIC include PRIVATE src)
target_compile_options(ble_core PRIVATE ${BLE_WARNINGS})

# Host unit tests.
add_executable(ble_tests
    tests/test_main.c
    tests/test_aes.c
    tests/test_rpa.c
    tests/test_ad.c
    tests/test_hci.c
    tests/test_fuzz.c)
target_link_libraries(ble_tests PRIVATE ble_core)
target_compile_options(ble_tests PRIVATE -Wall -Wextra -Werror)

# Host tool: parse HCI events given as hex lines, for the differential test.
add_executable(bleparse tools/bleparse.c)
target_link_libraries(bleparse PRIVATE ble_core)
target_compile_options(bleparse PRIVATE ${BLE_WARNINGS})

if(BLE_SANITIZE)
    foreach(t ble_core ble_tests bleparse)
        target_compile_options(${t} PRIVATE -fsanitize=address,undefined
                               -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
        target_link_options(${t} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

# Prove the library needs no libc: compile every source -ffreestanding.
add_library(ble_core_freestanding OBJECT
    src/ble_aes.c src/ble_rpa.c src/ble_ad.c src/ble_hci.c)
target_include_directories(ble_core_freestanding PRIVATE include src)
target_compile_options(ble_core_freestanding PRIVATE ${BLE_WARNINGS} -ffreestanding -fno-builtin)

enable_testing()
add_test(NAME unit COMMAND ble_tests)
