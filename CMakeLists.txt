cmake_minimum_required(VERSION 2.8.11)
project(mentohust_minimal C)
set(PROJECT_VERSION 0.4.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")

set(SOURCE_FILES
    src/dlfunc.c
    src/md5.c
    src/mentohust.c
    src/mycheck.c
    src/myconfig.c
    src/myfunc.c
    src/myini.c
    src/mystate.c
    src/byte_order.c
    src/checkV4.c
    src/rjmd5.c
    src/rjripemd128.c
    src/rjsha1.c
    src/rjtiger.c
    src/rjtiger_sbox.c
    src/rjwhirlpool.c
    src/rjwhirlpool_sbox.c)

option(NO_ENCODE_PASS
        "Do not encode password in configuration file" OFF)
option(NO_DYLOAD
        "Do not use dlopen() to load external libraries" ON)
option(NO_ARP
        "Do not process ARP info" OFF)
option(BUILD_OPENWRT
        "Build for OpenWRT" OFF)

configure_file("${PROJECT_SOURCE_DIR}/config.h.in" "${PROJECT_BINARY_DIR}/config.h")

include_directories("${PROJECT_BINARY_DIR}")

if (NO_DYLOAD)
    find_package(PCAP REQUIRED)
    set(LIBS ${LIBS} ${PCAP_LIBRARY})
else(NO_DYLOAD)
    set(LIBS ${LIBS} ${CMAKE_DL_LIBS})
endif(NO_DYLOAD)

add_executable(mentohust ${SOURCE_FILES})
target_link_libraries(mentohust ${LIBS})
install(TARGETS mentohust DESTINATION bin COMPONENT binaries)
