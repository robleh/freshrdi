#include "messagebox.hpp"
#include <Windows.h>

bool DllMain(void* base, unsigned long event, void*) {
    switch (event) {
    case DLL_PROCESS_ATTACH:
        MessageBoxW(nullptr, L"Test", L"Test", MB_OK);
    }
    return true;
}

__declspec(dllexport)
void test() {
    MessageBoxW(nullptr, L"Export", L"Test", MB_OK);
}