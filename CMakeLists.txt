cmake_minimum_required(VERSION 3.10)
project(MemoryManager LANGUAGES C)

# Library
add_library(MemoryManager handle_memory.c)

# Include directory
target_include_directories(MemoryManager 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Compiler options
target_compile_options(MemoryManager PRIVATE 
    -Wall -Wextra -std=c99
)

# Thread safety
option(ENABLE_THREAD_SAFE "Thread-safe operations" ON)
if(ENABLE_THREAD_SAFE)
    target_compile_definitions(MemoryManager PRIVATE MEM_THREAD_SAFE=1)
    find_package(Threads REQUIRED)
    target_link_libraries(MemoryManager PRIVATE Threads::Threads)
endif()

# Debug features
option(ENABLE_DEBUG "Debug features" OFF)
if(ENABLE_DEBUG)
    target_compile_definitions(MemoryManager PRIVATE DEBUG_MEMORY_MANAGER=1)
endif()

# Example (from test/example.c)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/example.c)
    add_executable(example test/example.c)
    target_link_libraries(example MemoryManager)
endif()

# Tests (from test/test.c)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test/test.c)
    enable_testing()
    add_executable(memory_test test/test.c)
    target_link_libraries(memory_test MemoryManager)
    add_test(NAME MemoryManagerTest COMMAND memory_test)
endif()

# Installation
install(TARGETS MemoryManager
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(FILES handle_memory.h DESTINATION include)