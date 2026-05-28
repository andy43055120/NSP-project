#include <windows.h>

int main() {
    void *mem = VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
    return 0;
}