# FindMemoryManager.cmake - CMake module to locate MemoryManager library
find_path(MemoryManager_INCLUDE_DIR handle_memory.h
    PATHS /usr/local/include /usr/include ${CMAKE_INSTALL_PREFIX}/include
)

find_library(MemoryManager_LIBRARY MemoryManager
    PATHS /usr/local/lib /usr/lib ${CMAKE_INSTALL_PREFIX}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MemoryManager DEFAULT_MSG
    MemoryManager_LIBRARY MemoryManager_INCLUDE_DIR
)

if(MemoryManager_FOUND AND NOT TARGET MemoryManager::MemoryManager)
    add_library(MemoryManager::MemoryManager UNKNOWN IMPORTED)
    set_target_properties(MemoryManager::MemoryManager PROPERTIES
        IMPORTED_LOCATION "${MemoryManager_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MemoryManager_INCLUDE_DIR}"
    )
    
    # Link pthreads if available (MemoryManager might need it)
    find_package(Threads QUIET)
    if(Threads_FOUND)
        set_target_properties(MemoryManager::MemoryManager PROPERTIES
            INTERFACE_LINK_LIBRARIES "Threads::Threads"
        )
    endif()
endif()