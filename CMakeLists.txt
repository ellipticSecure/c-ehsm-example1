cmake_minimum_required(VERSION 3.12)

project(c_ehsm_example1)

enable_language(C)

set(CMAKE_C_STANDARD 99)

add_subdirectory(ehsm-util-c ehsm-util-c)

add_executable(c_ehsm_example1 src/main.c)

target_include_directories(c_ehsm_example1
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(c_ehsm_example1
        PRIVATE ehsm-util-c
)
