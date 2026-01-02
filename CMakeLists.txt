cmake_minimum_required(VERSION 3.10)
project(libmemkit LANGUAGES C)

# Library
add_library(libmemkit memkit.c)

# Include directory
target_include_directories(libmemkit 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Compiler options
target_compile_options(libmemkit PRIVATE 
    -Wall -Wextra -std=c99
)

# Thread safety
option(ENABLE_THREAD_SAFE "Thread-safe operations" ON)
if(ENABLE_THREAD_SAFE)
    target_compile_definitions(libmemkit PRIVATE MEM_THREAD_SAFE=1)
    find_package(Threads REQUIRED)
    target_link_libraries(libmemkit PRIVATE Threads::Threads)
endif()

# Debug features
option(ENABLE_DEBUG "Debug features" OFF)
if(ENABLE_DEBUG)
    target_compile_definitions(libmemkit PRIVATE DEBUG_MEMORY_MANAGER=1)
endif()

# Example (from test/example.c)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/example.c)
    add_executable(example test/example.c)
    target_link_libraries(example libmemkit)
endif()

# Tests (from test/test.c)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/test.c)
    enable_testing()
    add_executable(memory_test test/test.c)
    target_link_libraries(memory_test libmemkit)
    add_test(NAME memkitTest COMMAND memory_test)
endif()

# Installation
install(TARGETS libmemkit
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(FILES memkit.h DESTINATION include)
