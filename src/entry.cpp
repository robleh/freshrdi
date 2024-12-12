#include "start.hpp"
#include <al/al.hpp>

extern"C"
int entry() {
    auto kernel32 = GM(L"KERNEL32.DLL", al::by_name);
    if (!kernel32) {
        return EXIT_FAILURE;
    }

    auto llw = GP(kernel32, LoadLibraryW, al::by_name);
    if (!llw) {
        return EXIT_FAILURE;
    }

    auto user32 = llw(L"user32.dll");
    if (!user32) {
        return EXIT_FAILURE;
    }

    auto mbw = GP(user32, MessageBoxW, al::by_name);
    if (!mbw) {
        return EXIT_FAILURE;
    }

    mbw(nullptr, L"Fight!", L"Round 1", MB_OK);
    return EXIT_SUCCESS;
}