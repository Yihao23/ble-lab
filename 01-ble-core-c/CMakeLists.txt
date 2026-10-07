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
    src/ble_hci.c
    src/ble_cmac.c
    src/ble_sc.c
    src/ble_l2cap.c
    src/ble_att.c)
target_include_directories(ble_core PUBLIC include PRIVATE src)
target_compile_options(ble_core PRIVATE ${BLE_WARNINGS})

# Host unit tests.
add_executable(ble_tests
    tests/test_main.c
    tests/test_aes.c
    tests/test_rpa.c
    tests/test_ad.c
    tests/test_ad_helpers.c
    tests/test_hci.c
    tests/test_hci_status.c
    tests/test_hci_multi.c
    tests/test_cmac.c
    tests/test_l2cap_att.c
    tests/test_reasm.c
    tests/test_fuzz.c)
target_link_libraries(ble_tests PRIVATE ble_core)
target_compile_options(ble_tests PRIVATE -Wall -Wextra -Werror)

# Host tool: parse HCI events given as hex lines, for the differential test.
add_executable(bleparse tools/bleparse.c)
target_link_libraries(bleparse PRIVATE ble_core)
target_compile_options(bleparse PRIVATE ${BLE_WARNINGS})

add_executable(aclparse tools/aclparse.c)
target_link_libraries(aclparse PRIVATE ble_core)
target_compile_options(aclparse PRIVATE ${BLE_WARNINGS})

add_executable(bleg2 tools/bleg2.c)
target_link_libraries(bleg2 PRIVATE ble_core)
target_compile_options(bleg2 PRIVATE ${BLE_WARNINGS})

# bleg2 takes values as SMP sends them, LSB first: the Appendix D.5 vector,
# byte-reversed, must still give the six digits the spec's g2 gives.
add_test(NAME bleg2_spec_vector COMMAND bleg2
    e69d350e480103ccdbfdf4ac1191f4efb9a5f9e9a7832c5e2cbe97f2d203b020
    fdc57ff449dd4f6bfb7c9df1c29acb592ae7d4eefbfc0a909abbf6323d8b1855
    abae2b71ecb2ffff3e7377d15484cbd5
    cfc43dfff78365216e5fa725cce7e8a6)
set_tests_properties(bleg2_spec_vector PROPERTIES PASS_REGULAR_EXPRESSION "g2 0x2f9ed5ba  compare value 938554")

if(BLE_SANITIZE)
    # Every target that links ble_core must be here: an executable linking the
    # instrumented library without the sanitizer runtime fails to link.
    foreach(t ble_core ble_tests bleparse bleg2 aclparse)
        target_compile_options(${t} PRIVATE -fsanitize=address,undefined
                               -fno-sanitize-recover=all -fno-omit-frame-pointer -g)
        target_link_options(${t} PRIVATE -fsanitize=address,undefined)
    endforeach()
endif()

# Prove the library needs no libc: compile every source -ffreestanding.
add_library(ble_core_freestanding OBJECT
    src/ble_aes.c src/ble_rpa.c src/ble_ad.c src/ble_hci.c src/ble_cmac.c src/ble_sc.c src/ble_l2cap.c src/ble_att.c)
target_include_directories(ble_core_freestanding PRIVATE include src)
target_compile_options(ble_core_freestanding PRIVATE ${BLE_WARNINGS} -ffreestanding -fno-builtin)

enable_testing()
add_test(NAME unit COMMAND ble_tests)
