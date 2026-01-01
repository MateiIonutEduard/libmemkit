#include "handle_memory.h"
#include <stdio.h>

int main(void) {
    MemoryPool pool;
    if (!mem_pool_init(&pool, 16)) {
        fprintf(stderr, "Failed to initialize pool.\n");
        return 1;
    }

    MemoryPointer* ptr = mem_pointer_create("example_buffer", 1024);
	
    if (!ptr) {
        fprintf(stderr, "Failed to create pointer.\n");
        return 1;
    }

    if (mem_pointer_allocate(ptr, 1024, &pool)) {
        printf("Successfully allocated %zu bytes.\n", ptr->container->size);
        
        /* use the memory */
        int* data = (int*)ptr->container->data;
        data[0] = 42;
        printf("Stored value: %d.\n", data[0]);
    }

    mem_pointer_destroy(ptr, &pool);
    mem_pool_destroy(&pool);
    return 0;
}