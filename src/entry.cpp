#include "freshrdi.hpp"
#include "messagebox.dll.hpp"
#include <al/al.hpp>
#include <algorithm>

data_dirs parse_data(headers* pe) {
    data_dirs data{};

    PIMAGE_DATA_DIRECTORY dir = &pe->data[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir->Size && dir->VirtualAddress) {
        data.relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pe->va + dir->VirtualAddress);
    }

    dir = &pe->data[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir->Size && dir->VirtualAddress) {
        data.imports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pe->va + dir->VirtualAddress);
    }

    dir = &pe->data[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->Size && dir->VirtualAddress) {
        data.exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(pe->va + dir->VirtualAddress);
    }

    dir = &pe->data[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (dir->Size && dir->VirtualAddress) {
        data.load_config = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(pe->va + dir->VirtualAddress);
    }

    dir = &pe->data[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir->Size && dir->VirtualAddress) {
        data.tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pe->va + dir->VirtualAddress);
    }

    dir = &pe->data[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir->Size && dir->VirtualAddress) {
        data.tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pe->va + dir->VirtualAddress);
    }

    dir = &pe->data[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (dir->Size && dir->VirtualAddress) {
        data.exceptions = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(pe->va + dir->VirtualAddress);
        data.exceptions_size = dir->Size;
    }

    return data;
}

headers parse_headers(void* base) {
    headers h{
        .base = static_cast<std::byte*>(base),
        .va = reinterpret_cast<uintptr_t>(base),
        .dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base)
    };

    h.nt = reinterpret_cast<PIMAGE_NT_HEADERS>(h.base + h.dos->e_lfanew);
    h.opt = &(h.nt->OptionalHeader);
    h.file = &(h.nt->FileHeader);
    h.data = h.opt->DataDirectory;
    h.size = h.opt->SizeOfHeaders;

    return h;
}

extern "C" error entry() {
    // Parse the unmapped PE
    headers dll_headers = parse_headers(embedded::messagebox.data());

    auto ntdll = GM(L"ntdll.dll", al::by_djb2);
    if (!ntdll) {
        return error::NTDLL;
    }

    auto kernel32 = GM(L"KERNEL32.DLL", al::by_djb2);
    if (!kernel32) {
        return error::KERNEL32;
    }

    auto kernelbase = GM(L"kernelbase.dll", al::by_djb2);
    if (!kernelbase) {
        return error::KERNELBASE;
    }

    auto virtual_alloc = GP(kernel32, VirtualAlloc, al::by_djb2);
    if (!virtual_alloc) {
        return error::VIRTUALALLOC;
    }

    auto get_module_handle = GP(kernel32, GetModuleHandleA, al::by_djb2);
    if (!get_module_handle) {
        return error::GETMODULEHANDLEA;
    }

    auto load_library = GP(kernel32, LoadLibraryA, al::by_djb2);
    if (!load_library) {
        return error::LOADLIBRARYA;
    }

    auto get_proc_address = GP(kernel32, GetProcAddress, al::by_djb2);
    if (!get_proc_address) {
        return error::GETPROCADDRESS;
    }

    auto virtual_protect = GP(kernel32, VirtualProtect, al::by_djb2);
    if (!virtual_protect) {
        return error::VIRTUALPROTECT;
    }

    auto flush_instruction_cache = GP(
        kernel32,
        FlushInstructionCache,
        al::by_djb2
    );
    if (!flush_instruction_cache) {
        return error::FLUSHINSTRUCTIONCACHE;
    }

    auto add_function_table = GP(kernel32, RtlAddFunctionTable, al::by_djb2);
    if (!add_function_table) {
        return error::RTLADDFUNCTIONTABLE;
    }

    auto set_process_valid_call_targets = GP(
        kernelbase,
        SetProcessValidCallTargets,
        al::by_djb2
    );
    if (!set_process_valid_call_targets) {
        return error::SETPROCESSVALIDCALLTARGETS;
    }

    void* buf = virtual_alloc(
        nullptr,
        dll_headers.opt->SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!buf) {
        return error::VIRTUALALLOC;
    }
    auto va = reinterpret_cast<uintptr_t>(buf);

    // Map the payload headers in immediately and account for their new VA.
    std::copy_n(dll_headers.base, dll_headers.opt->SizeOfHeaders, static_cast<std::byte*>(buf));

    // Track the delta needed for our relocation adjustments.
    ptrdiff_t delta = va - dll_headers.opt->ImageBase;

    // Map the raw sections to their respective virtual addresses.
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(dll_headers.nt);
    for (unsigned short i = 0; i < dll_headers.file->NumberOfSections; ++i) {
        std::copy_n(
            reinterpret_cast<std::byte*>(dll_headers.va + sections[i].PointerToRawData),
            sections[i].SizeOfRawData,
            reinterpret_cast<std::byte*>(va + sections[i].VirtualAddress)
        );
    }

    headers new_headers = parse_headers(buf);
    data_dirs data = parse_data(&new_headers);

    // Process relocations
    if (delta && data.relocations) {
        // Loop over blocks
        while (data.relocations->VirtualAddress) {
            unsigned short n = (data.relocations->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_RECORD);

            // The relocation entries start after the block's header
            auto reloc = reinterpret_cast<PIMAGE_RELOCATION_RECORD>(data.relocations + 1);

            // Loop over relocations in the block
            for (; n > 0; --n) {
                auto ptr = reinterpret_cast<uintptr_t*>(va + data.relocations->VirtualAddress + reloc->Offset);

                switch (reloc->Type) {
                case IMAGE_REL_BASED_DIR64:
                    *ptr += delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *ptr += static_cast<DWORD>(delta);
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *ptr += HIWORD(delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *ptr += LOWORD(delta);
                    break;
                }

                ++reloc;
            }

            // The end of the list is the beginning of the next block.
            data.relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reloc);
        }
    }

    // Imports
    //
    // We skip delay load imports because we know our payload does not have
    // them.
    if (data.imports) {
        while (data.imports->Characteristics) {
            auto og_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(va + data.imports->OriginalFirstThunk);
            auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(va + data.imports->FirstThunk);

            // We do not want to call LoadLibrary during the verifier
            // notification. Instead, we rely on these DLLs already being
            // brought in by the loader DLL.
            HMODULE dll = load_library(reinterpret_cast<const char*>(va + data.imports->Name));

            if (!dll) {
                return error::FAIL_LOAD_LIBRARY;
            }

            for (; og_first_thunk->u1.Function; ++first_thunk, ++og_first_thunk) {
                if (IMAGE_SNAP_BY_ORDINAL(og_first_thunk->u1.Ordinal)) {
                    FARPROC address = get_proc_address(
                        dll,
                        MAKEINTRESOURCEA(og_first_thunk->u1.Ordinal)
                    );
                    if (!address) {
                        return error::FAIL_GET_PROC;
                    }

                    first_thunk->u1.Function = reinterpret_cast<uintptr_t>(address);
                }
                else {
                    auto named_import = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(va + og_first_thunk->u1.AddressOfData);

                    FARPROC address = get_proc_address(
                        dll,
                        static_cast<const char*>(named_import->Name)
                    );
                    if (!address) {
                        return error::FAIL_GET_PROC;
                    }

                    first_thunk->u1.Function = reinterpret_cast<uintptr_t>(address);
                }
            }
            ++data.imports;
        }
    }

    // Adjust section memory protections
    bool r, w, x;
    unsigned long protect;
    for (unsigned short i = 0; i < dll_headers.file->NumberOfSections; ++i) {
        if (sections[i].SizeOfRawData) {
            // determine protection flags based on characteristics
            bool r = (sections[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
            bool w = (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            bool x = (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

            if (!x && !r && !w)
                protect = PAGE_NOACCESS;
            else if (!x && !r && w)
                protect = PAGE_WRITECOPY;
            else if (!x && r && !w)
                protect = PAGE_READONLY;
            else if (!x && r && w)
                protect = PAGE_READWRITE;
            else if (x && !r && !w)
                protect = PAGE_EXECUTE;
            else if (x && !r && w)
                protect = PAGE_EXECUTE_WRITECOPY;
            else if (x && r && !w)
                protect = PAGE_EXECUTE_READ;
            else if (x && r && w)
                protect = PAGE_EXECUTE_READWRITE;

            if (sections[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
                protect |= PAGE_NOCACHE;
            }
        }

        if (!virtual_protect(
            reinterpret_cast<void*>(va + sections[i].VirtualAddress),
            sections[i].SizeOfRawData,
            protect,
            &protect
        )) {
            return error::FAIL_PROTECT;
        }
    }

    // Flush instruction cache
    // -1 is pseudo handle to current process.
    if (!flush_instruction_cache(reinterpret_cast<HANDLE>(-1), NULL, 0)) {
        return error::FAIL_FLUSH_CACHE;
    }

    auto entry = reinterpret_cast<PIMAGE_CFG_ENTRY>(data.load_config->GuardCFFunctionTable);
    if (entry) {
        for (size_t i = 0; i <= data.load_config->GuardCFFunctionCount; ++i) {
            CFG_CALL_TARGET_INFO cfg{
                .Offset = entry[i].Rva,
                .Flags = CFG_CALL_TARGET_VALID
            };

            set_process_valid_call_targets(
                reinterpret_cast<HANDLE>(-1),
                dll_headers.base,
                dll_headers.opt->SizeOfImage,
                1,
                &cfg
            );
        }
    }

    // TLS callbacks
    if (data.tls) {
        auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(data.tls->AddressOfCallBacks);

        for (; *callback; ++callback) {
            (*callback)(buf, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // SEH exceptions
    if (data.exceptions)
    {
        if (!add_function_table(data.exceptions, (data.exceptions_size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, va)) {
            return error::FAIL_ADD_FUNCTION_TABLE;
        }
    }

    auto dll_main = reinterpret_cast<dll_main_t>(va + dll_headers.opt->AddressOfEntryPoint);
    if (!dll_main(static_cast<HINSTANCE>(buf), DLL_PROCESS_ATTACH, nullptr)) {
        return error::DLLMAIN;
    }

    auto functions = reinterpret_cast<unsigned long*>(va + data.exports->AddressOfFunctions);
    auto test_export = reinterpret_cast<decltype(&test)>(va + functions[0]);
    if (!test_export) {
        return error::DLLMAIN;
    }

    test_export();

    return error::SUCCESS;
}
