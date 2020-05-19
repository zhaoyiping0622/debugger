cmake_minimum_required(VERSION 3.10)
project(debugger C)

set(CMAKE_C_STANDARD 99)

add_executable(debugger main.c)
add_executable(run run.c)
add_executable(death death.c)
