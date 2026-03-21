cmake_minimum_required(VERSION 3.20)
project(BAIT C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Warnings — you want these
add_compile_options(-Wall -Wextra -Wpedantic)

add_subdirectory(lib)
add_subdirectory(tests)
# add_subdirectory(patcher)   # uncomment when ready
# add_subdirectory(debugger)  # uncomment when ready

add_library(bait_lib STATIC
        elf_parser.c
)

target_include_directories(bait_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(test_parser
        test.c
)

target_link_libraries(test_parser PRIVATE
        bait_lib
)