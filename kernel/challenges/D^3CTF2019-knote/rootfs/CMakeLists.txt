cmake_minimum_required(VERSION 3.23)
project(rootfs C)

set(CMAKE_C_STANDARD 11)

add_executable(rootfs
        myexp.c)
