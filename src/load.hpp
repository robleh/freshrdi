#pragma once
#include <phnt.h>
#include <span>
#include <stdint.h>

// Add error enum
enum error {
    SUCCESS,
    NTDLL,
    KERNEL32,
    KERNELBASE,
    DECOYDLL,
    VIRTUALALLOC,
    GETMODULEHANDLEA,
    LOADLIBRARYA,
    GETPROCADDRESS,
    VIRTUALPROTECT,
    FLUSHINSTRUCTIONCACHE,
    RTLADDFUNCTIONTABLE,
    SETPROCESSVALIDCALLTARGETS,
    FAIL_ALLOCATION,
    FAIL_LOAD_LIBRARY,
    FAIL_GET_PROC,
    FAIL_PROTECT,
    FAIL_FLUSH_CACHE,
    FAIL_ADD_FUNCTION_TABLE,
    DLLMAIN
};

#pragma pack(push, 1)
typedef struct _IMAGE_CFG_ENTRY {
    ULONG Rva;
    struct {
        BOOLEAN SuppressedCall : 1;
        BOOLEAN ExportSuppressed : 1;
        BOOLEAN LangExcptHandler : 1;
        BOOLEAN Xfg : 1;
        BOOLEAN Reserved : 4;
    };
} IMAGE_CFG_ENTRY, * PIMAGE_CFG_ENTRY;
#pragma pack(pop)

using dll_main_t = BOOL(*) (HINSTANCE, DWORD, LPVOID);

class loader {
    HMODULE                m_ntdll = nullptr;
    HMODULE                m_kernel32 = nullptr;

    void*                  m_buf = nullptr;
    uintptr_t              m_buf_va = 0;
    PIMAGE_NT_HEADERS      m_buf_nt = nullptr;
    PIMAGE_FILE_HEADER     m_buf_file = nullptr;
    PIMAGE_OPTIONAL_HEADER m_buf_opt = nullptr;

    void*                  m_base = nullptr;
    uintptr_t              m_va = 0;
    PIMAGE_DOS_HEADER      m_dos = nullptr;
    PIMAGE_NT_HEADERS      m_nt = nullptr;
    PIMAGE_FILE_HEADER     m_file = nullptr;
    PIMAGE_OPTIONAL_HEADER m_opt = nullptr;
    PIMAGE_DATA_DIRECTORY  m_data = nullptr;
    size_t                 m_size = 0;

    error allocate();
    error write();
    void  relocate();
    error protect_sections();
    error resolve_imports();
    error flush_cache();
    error enable_cfg();
    error enable_seh();
    error call_tls_callbacks();
    error call_dllmain();

public:
    loader(std::span<uint8_t> dll);
    void load();
};