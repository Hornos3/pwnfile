cmake_minimum_required(VERSION 3.22)
project(rootfs C)

set(CMAKE_C_STANDARD 11)

add_executable(rootfs
        myexp.c uffdexploit.c)
