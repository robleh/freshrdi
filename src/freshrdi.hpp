# pragma once
#include "messagebox.hpp"
#include "load.hpp"
#include <cstddef>

using export_t = decltype(&test);

extern "C" error entry();
using freshrdi_t = decltype(&entry);