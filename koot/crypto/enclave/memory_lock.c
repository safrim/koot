#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Helper function to cryptographically wipe memory, bypassing compiler optimizations
static void secure_wipe(void *v, size_t n) {
#if defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(v, n);
#elif defined(__APPLE__)
    memset_s(v, n, 0, n);
#elif defined(__linux__)
    explicit_bzero(v, n);
#else
    // Fallback using volatile pointer if OS-specific secure wipe isn't available
    volatile unsigned char *p = v;
    while (n--) *p++ = 0;
#endif
}

// Allocate and lock memory (preventing it from being swapped to disk)
void* allocate_secure_key(size_t size) {
    if (size == 0) return NULL;
    
    void *ptr = malloc(size);
    if (!ptr) return NULL;

#if defined(_WIN32) || defined(_WIN64)
    if (!VirtualLock(ptr, size)) {
        free(ptr);
        return NULL;
    }
#else
    // mlock locks the physical pages in RAM
    if (mlock(ptr, size) != 0) {
        free(ptr);
        return NULL;
    }
#endif

    return ptr;
}

// Unlock, cryptographically wipe, and free memory
void destroy_secure_key(void *ptr, size_t size) {
    if (!ptr || size == 0) return;

    // 1. Wipe the memory explicitly
    secure_wipe(ptr, size);

    // 2. Unlock the memory back to the OS
#if defined(_WIN32) || defined(_WIN64)
    VirtualUnlock(ptr, size);
#else
    munlock(ptr, size);
#endif

    // 3. Free the allocation
    free(ptr);
}