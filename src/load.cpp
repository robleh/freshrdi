#include "load.hpp"
#include <al/al.hpp>
#include <cstddef>

loader::loader(std::span<uint8_t> dll) : m_buf(dll.data()) {
    m_ntdll    = GM(L"ntdll.dll", al::by_djb2);
    m_kernel32 = GM(L"KERNEL32.DLL", al::by_djb2);

    auto dos   = reinterpret_cast<PIMAGE_DOS_HEADER>(dll.data());
    m_buf_va   = reinterpret_cast<uintptr_t>(dos);
    m_buf_nt   = reinterpret_cast<PIMAGE_NT_HEADERS>(m_buf_va + dos->e_lfanew);
    m_buf_opt  = &m_buf_nt->OptionalHeader;
    m_buf_file = &m_buf_nt->FileHeader;
}

void loader::load() {
    allocate();
    write();

    m_va    = reinterpret_cast<uintptr_t>(m_base);
    m_dos   = reinterpret_cast<PIMAGE_DOS_HEADER>(m_base);
    m_nt    = reinterpret_cast<PIMAGE_NT_HEADERS>(m_va + m_dos->e_lfanew);
    m_opt   = &m_nt->OptionalHeader;
    m_file  = &m_nt->FileHeader;
    m_data  = m_opt->DataDirectory;

    relocate();
    resolve_imports();
    protect_sections();
    flush_cache();
    enable_cfg();
    enable_seh();
    call_tls_callbacks();
    call_dllmain();
}

error loader::allocate() {
    auto virtual_alloc = GP(m_kernel32, VirtualAlloc, al::by_djb2);
    if (!virtual_alloc) {
        return error::VIRTUALALLOC;
    }

    m_base = virtual_alloc(
        nullptr,
        m_buf_opt->SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!m_base) {
        return error::VIRTUALALLOC;
    }

    m_va = reinterpret_cast<uintptr_t>(m_base);
    return error::SUCCESS;
}

error loader::write() {
    // Map headers
    std::copy_n(
        static_cast<std::byte*>(m_buf),
        m_buf_opt->SizeOfHeaders,
        static_cast<std::byte*>(m_base)
    );

    // Map raw sections to their virtual addresses
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(m_buf_nt);
    for (unsigned short i = 0; i < m_buf_file->NumberOfSections; ++i) {
        std::copy_n(
            reinterpret_cast<std::byte*>(m_buf_va + sec[i].PointerToRawData),
            sec[i].SizeOfRawData,
            reinterpret_cast<std::byte*>(m_va + sec[i].VirtualAddress)
        );
    }
    return error::SUCCESS;
}

void loader::relocate() {
    ptrdiff_t delta = m_va - m_opt->ImageBase;
    if (!delta) {
        return;
    }

    auto dir = m_data[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) {
        return;
    }

    auto relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(m_va + dir.VirtualAddress);
    
    if (!relocations) {
        return;
    }

    // Loop over blocks
    while (relocations->VirtualAddress) {
        unsigned short n = (relocations->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_RECORD);

        // The relocation entries start after the block's header
        auto record = reinterpret_cast<PIMAGE_RELOCATION_RECORD>(relocations + 1);

        // Loop over relocations in the block
        for (; n > 0; --n) {
            auto ptr = reinterpret_cast<uintptr_t*>(m_va + relocations->VirtualAddress + record->Offset);

            switch (record->Type) {
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

            ++record;
        }

        // The end of the list is the beginning of the next block.
        relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(record);
    }
}

error loader::resolve_imports() {
    auto load_library = GP(m_kernel32, LoadLibraryA, al::by_djb2);
    if (!load_library) {
        return error::LOADLIBRARYA;
    }

    auto get_proc_address = GP(m_kernel32, GetProcAddress, al::by_djb2);
    if (!get_proc_address) {
        return error::GETPROCADDRESS;
    }

    auto dir = m_data[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) {
        return error::SUCCESS;
    }

    auto descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(m_va + dir.VirtualAddress);
    
    if (!descriptor) {
        return error::SUCCESS;
    }

    while (descriptor->Characteristics) {
        auto og_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(m_va + descriptor->OriginalFirstThunk);
        auto first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(m_va + descriptor->FirstThunk);

        // We do not want to call LoadLibrary during the verifier
        // notification. Instead, we rely on these DLLs already being
        // brought in by the loader DLL.
        HMODULE dll = load_library(reinterpret_cast<const char*>(m_va + descriptor->Name));

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
                auto named_import = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(m_va + og_first_thunk->u1.AddressOfData);

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
        ++descriptor;
    }
    return error::SUCCESS;
}

error loader::protect_sections() {
    auto virtual_protect = GP(m_kernel32, VirtualProtect, al::by_djb2);
    if (!virtual_protect) {
        return error::VIRTUALPROTECT;
    }

    // Adjust section memory protections
    bool r, w, x;
    unsigned long protect = 0;
    auto sec = IMAGE_FIRST_SECTION(m_nt);
    for (unsigned short i = 0; i < m_file->NumberOfSections; ++i) {
        if (sec[i].SizeOfRawData) {
            // determine protection flags based on characteristics
            bool r = (sec[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
            bool w = (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            bool x = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

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

            if (sec[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
                protect |= PAGE_NOCACHE;
            }
        }

        if (!virtual_protect(
            reinterpret_cast<void*>(m_va + sec[i].VirtualAddress),
            sec[i].SizeOfRawData,
            protect,
            &protect
        )) {
            return error::FAIL_PROTECT;
        }
    }
    return error::SUCCESS;
}

error loader::flush_cache() {
    auto flush_instruction_cache = GP(
        m_kernel32,
        FlushInstructionCache,
        al::by_djb2
    );
    if (!flush_instruction_cache) {
        return error::FLUSHINSTRUCTIONCACHE;
    }

    // Flush instruction cache
    // -1 is pseudo handle to current process.
    if (!flush_instruction_cache(reinterpret_cast<HANDLE>(-1), nullptr, 0)) {
        return error::FAIL_FLUSH_CACHE;
    }

    return error::SUCCESS;
}

error loader::enable_cfg() {
    auto kernelbase = GM(L"kernelbase.dll", al::by_djb2);
    if (!kernelbase) {
        return error::KERNELBASE;
    }

    auto set_process_valid_call_targets = GP(
        kernelbase,
        SetProcessValidCallTargets,
        al::by_djb2
    );
    if (!set_process_valid_call_targets) {
        return error::SETPROCESSVALIDCALLTARGETS;
    }

    auto dir = m_data[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!dir.VirtualAddress || !dir.Size) {
        return error::SUCCESS;
    }

    auto load_config = reinterpret_cast<PIMAGE_LOAD_CONFIG_DIRECTORY>(m_va + dir.VirtualAddress);
    if (!load_config) {
        return error::SUCCESS;
    }

    auto entry = reinterpret_cast<PIMAGE_CFG_ENTRY>(load_config->GuardCFFunctionTable);
    if (!entry) {
        return error::SUCCESS;
    }

    for (size_t i = 0; i <= load_config->GuardCFFunctionCount; ++i) {
        CFG_CALL_TARGET_INFO cfg{
            .Offset = entry[i].Rva,
            .Flags = CFG_CALL_TARGET_VALID
        };

        set_process_valid_call_targets(
            reinterpret_cast<HANDLE>(-1),
            reinterpret_cast<void*>(m_dos),
            m_opt->SizeOfImage,
            1,
            &cfg
        );
    }
    return error::SUCCESS;
}

error loader::enable_seh() {
    auto add_function_table = GP(m_kernel32, RtlAddFunctionTable, al::by_djb2);
    if (!add_function_table) {
        return error::RTLADDFUNCTIONTABLE;
    }

    auto dir = m_data[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir.VirtualAddress || !dir.Size) {
        return error::SUCCESS;
    }

    auto entry = reinterpret_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(m_va + dir.VirtualAddress);
    if (!entry) {
        return error::SUCCESS;
    }

    if (!add_function_table(entry, (dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1, m_va)) {
        return error::FAIL_ADD_FUNCTION_TABLE;
    }
    return error::SUCCESS;
}

error loader::call_tls_callbacks() {
    auto dir = m_data[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.VirtualAddress || !dir.Size) {
        return error::SUCCESS;
    }

    auto tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(m_va + dir.VirtualAddress);
    if (!tls) {
        return error::SUCCESS;
    }

    auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);

    for (; *callback; ++callback) {
        (*callback)(m_base, DLL_PROCESS_ATTACH, nullptr);
    }
    return error::SUCCESS;
}

error loader::call_dllmain() {
    auto dll_main = reinterpret_cast<dll_main_t>(m_va + m_opt->AddressOfEntryPoint);
    if (!dll_main(static_cast<HINSTANCE>(m_base), DLL_PROCESS_ATTACH, nullptr)) {
        return error::DLLMAIN;
    }
    return error::SUCCESS;
}
