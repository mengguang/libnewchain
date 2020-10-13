cmake_minimum_required(VERSION 3.15)

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    #set cmake option -DCMAKE_TOOLCHAIN_FILE=c:/dev/vcpkg/scripts/buildsystems/vcpkg.cmake
endif()

project(libnewchain)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)

include_directories(trezor)

AUX_SOURCE_DIRECTORY(./trezor DIR_SRCS)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")


add_executable(${PROJECT_NAME}
        main.c
        jsmn/jsmn.c
        keystore.c
        misc.c
        newchain.c
        misc.c
        tiny-aes-c/tinyaes.c
        micro-ecc/uECC.c
        ${DIR_SRCS}
        portable_utils.c portable_utils.h)

