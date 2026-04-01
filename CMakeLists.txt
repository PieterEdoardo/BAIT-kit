cmake_minimum_required(VERSION 3.20)
project(BAIT C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic)

add_library(bait_lib STATIC
        lib/elf_parser.c
)

target_include_directories(bait_lib PUBLIC
        ${PROJECT_SOURCE_DIR}/lib
)

add_executable(test_parser
        tests/test.c
)

target_link_libraries(test_parser PRIVATE
        bait_lib
)