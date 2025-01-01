#include "freshrdi.hpp"
#include "messagebox.dll.hpp"

extern "C" error entry() {
    loader ldr{ embedded::messagebox };
    ldr.load();
    return error::SUCCESS;
}
