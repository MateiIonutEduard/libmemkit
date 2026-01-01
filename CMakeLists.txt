cmake_minimum_required(VERSION 3.10)
project(MemoryManager LANGUAGES C)

# Library
add_library(MemoryManager handle_memory.c)

# Public headers
target_include_directories(MemoryManager 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# Compile options
target_compile_options(MemoryManager PRIVATE 
    -Wall -Wextra -std=c99
)

# Thread safety (optional)
option(ENABLE_THREAD_SAFE "Thread-safe operations" ON)
if(ENABLE_THREAD_SAFE)
    target_compile_definitions(MemoryManager PRIVATE MEM_THREAD_SAFE=1)
    find_package(Threads REQUIRED)
    target_link_libraries(MemoryManager PRIVATE Threads::Threads)
endif()

# Debug features (optional)
option(ENABLE_DEBUG "Debug features" OFF)
if(ENABLE_DEBUG)
    target_compile_definitions(MemoryManager PRIVATE DEBUG_MEMORY_MANAGER=1)
endif()

# Installation
install(TARGETS MemoryManager
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(FILES handle_memory.h DESTINATION include)
