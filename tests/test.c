#include "handle_memory.h"
#include <assert.h>
#include <stdio.h>

void test_basic_allocation(void) {
    MemoryPool pool;
    assert(mem_pool_init(&pool, 8));
    
    MemoryPointer* ptr = mem_pointer_create("test", 0);
    assert(ptr);
    
    assert(mem_pointer_allocate(ptr, 100, &pool));
    assert(ptr->container->data != NULL);
    assert(ptr->container->size >= 100);
    
    mem_pointer_destroy(ptr, &pool);
    mem_pool_destroy(&pool);
    printf("Basic allocation test passed.\n");
}

void test_arena_allocation(void) {
    MemoryArena* arena = mem_arena_create(4096);
    assert(arena);
    
    int* arr = mem_arena_alloc(arena, 100 * sizeof(int));
    assert(arr);
    
    for (int i = 0; i < 100; i++)
        arr[i] = i;
    
    mem_arena_destroy(arena);
    printf("Arena allocation test passed.\n");
}

int main(void) {
    printf("Running MemoryManager tests...\n");
    test_basic_allocation();
    test_arena_allocation();
    printf("All tests passed!\n");
    return 0;
}