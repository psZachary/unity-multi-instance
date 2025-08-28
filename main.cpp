#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <ShlObj.h>
#include <propkey.h>
#pragma comment(lib, "Version.lib")

const wchar_t* supported_unity_versions[128] = {
    L"2022.3.62f1",
    L"2022.3.41f1"
};

static void print_usage() {
    std::cout << "usage: unity-multi-instance.exe <image name>" << std::endl;
    std::cout << "example: unity-multi-instance.exe \"RustClient.exe\"" << std::endl;
}

static bool rpm(HANDLE h, uintptr_t addr, void* out, SIZE_T size) {
    SIZE_T read = 0;
    return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), out, size, &read) && read == size;
}

static bool wpm(HANDLE h, uintptr_t addr, void* buffer, SIZE_T size) {
    SIZE_T written = 0;
    return WriteProcessMemory(h, reinterpret_cast<LPVOID>(addr), buffer, size, &written) && written == size;
}

struct section_info {
    uintptr_t base;
    size_t size;
};

static bool get_image_section_info(HANDLE process, uintptr_t image_base, const char* section_name, section_info* p_sinfo) {
    if (!process || !image_base || !section_name) return 0;

    IMAGE_DOS_HEADER dos{};
    if (!rpm(process, image_base, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    struct NT_LEADER {
        DWORD signature;
        IMAGE_FILE_HEADER fileheader;
    } nt_leader{};

    const uintptr_t nt_addr = image_base + static_cast<uintptr_t>(dos.e_lfanew);
    if (!rpm(process, nt_addr, &nt_leader, sizeof(nt_leader))) return 0;
    if (nt_leader.signature != IMAGE_NT_SIGNATURE) return 0;

    const WORD num_sections = nt_leader.fileheader.NumberOfSections;
    const WORD size_of_optional = nt_leader.fileheader.SizeOfOptionalHeader;

    const uintptr_t sections_addr =
        nt_addr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + static_cast<uintptr_t>(size_of_optional);

    for (WORD i = 0; i < num_sections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        const uintptr_t sh_addr = sections_addr + static_cast<uintptr_t>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (!rpm(process, sh_addr, &sh, sizeof(sh))) return 0;

        char name[9] = {};
        std::memcpy(name, sh.Name, 8);

        if (std::strncmp(name, section_name, 8) == 0) {
            p_sinfo->base = image_base + static_cast<uintptr_t>(sh.VirtualAddress);
            p_sinfo->size = sh.Misc.VirtualSize;
            break;
        }
    }

    return 1;
}

static bool match_signature(const uint8_t* data, const char* sig) {
    for (size_t i = 0; sig[i]; i += 3) {
        if (sig[i] == '?') continue;
        unsigned int byte;
        sscanf_s(&sig[i], "%2x", &byte);
        if (data[i / 3] != static_cast<uint8_t>(byte))
            return false;
    }
    return true;
}

static uintptr_t sig_scan(HANDLE process, uintptr_t module_base, size_t size, const char* signature) {
    constexpr size_t    chunk_size = 0x10000;
    size_t              bytes_read = 0;
    uint8_t*            buffer = new uint8_t[chunk_size]{};
    

    while (bytes_read < size) {
        size_t to_read = (size - bytes_read < chunk_size) ? (size - bytes_read) : chunk_size;

        if (!rpm(process, module_base + bytes_read, buffer, to_read))
            return 0;

        for (size_t i = 0; i < to_read; i++) {
            if (match_signature(&buffer[i], signature)) {
                return module_base + bytes_read + i;
            }
        }

        bytes_read += to_read;
    }

    delete[] buffer;
    return 0;
}

using t_on_image_loaded = bool(*)(HANDLE h, uintptr_t, wchar_t* image_path);

static bool wait_for_module_load(PROCESS_INFORMATION pi, const wchar_t* mod_name, t_on_image_loaded on_load) {
    DEBUG_EVENT         dbg{};
    uintptr_t           module_base = 0;
    wchar_t             module_name[MAX_PATH]{};
    bool                found = false;

    while (WaitForDebugEvent(&dbg, INFINITE)) {
        switch (dbg.dwDebugEventCode) {

        case LOAD_DLL_DEBUG_EVENT: {
            auto& ev = dbg.u.LoadDll;
            uintptr_t base = reinterpret_cast<uintptr_t>(ev.lpBaseOfDll);

            if (ev.lpImageName && ev.fUnicode) {
                LPVOID remote_buffer = nullptr;

                if (!rpm(pi.hProcess, (uintptr_t)ev.lpImageName, &remote_buffer, sizeof(remote_buffer)) || !remote_buffer)
                    return false;

                if (!rpm(pi.hProcess, (uintptr_t)remote_buffer, module_name, sizeof(module_name)))
                    return false;

            }

            if (wcsstr(module_name, mod_name) != 0) {
                if (!on_load(pi.hProcess, base, module_name))
                    return false;

                found = true;
                break;
            }

            if (ev.hFile)
                CloseHandle(ev.hFile);

            break;
        }
        default:
            break;
        }

        ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);

        if (found) {
            DebugActiveProcessStop(pi.dwProcessId);
            return true;
        }
    }

    return true;
}
static bool get_product_version(const wchar_t* path, wchar_t** version) {
    struct LANGANDCODEPAGE  { WORD w_language; WORD w_codepage; };
    LANGANDCODEPAGE*        lp_translate = nullptr;
    UINT                    cb_translate = 0;
    uint8_t                 file_version_buffer[2048]{};
    wchar_t                 blk_sub[50];
    DWORD                   handle = 0;
    DWORD                   size = 0;
    wchar_t*                value = nullptr;
    UINT                    size_out = 0;

    if (!path || !version)
        return false;

    size = GetFileVersionInfoSizeW(path, &handle);
    if (size == 0)
        return false;

    if (!GetFileVersionInfoW(path, 0, size, file_version_buffer))
        return false;

    if (!VerQueryValueW(file_version_buffer, L"\\VarFileInfo\\Translation",
        (LPVOID*)&lp_translate, &cb_translate))
        return L"";

    swprintf_s(blk_sub, L"\\StringFileInfo\\%04x%04x\\ProductVersion",
        lp_translate[0].w_language, lp_translate[0].w_codepage);

    if (VerQueryValueW(file_version_buffer, blk_sub, (LPVOID*)version, &size_out))
    {
        return true;
    }

    return false;
}

bool split_string(const wchar_t* wstr, wchar_t delimiter, wchar_t* out, size_t index) {
    if (!wstr || !out) return false;

    size_t cur = 0;
    const wchar_t* p = wstr;

    while (*p) {
        while (*p == delimiter)
            ++p;

        if (!*p) break;

        const wchar_t* start = p;
        while (*p && *p != delimiter)
            ++p;

        if (cur == index) {
            size_t len = static_cast<size_t>(p - start);
            wmemcpy(out, start, len);
            out[len] = L'\0';
            return true;
        }
        ++cur;
    }

    return false;
}

static bool unityplayer_version_supported(const wchar_t* image_path, bool* supported, wchar_t* version) {
    wchar_t     delimited_product_version[128]{};
    wchar_t*    product_version = nullptr;

    if (!supported || !version || !image_path) return false;

    if (!get_product_version(image_path, (wchar_t**)&product_version))
    {
        std::cout << "failed to get product version: " << GetLastError() << std::endl;
        return false;
    }

    if (!split_string(product_version, ' ', delimited_product_version, 0)) {
        std::cout << "failed to deliminate string: " << GetLastError() << std::endl;
        return false;
    }

    if (!wmemcpy(version, product_version, wcslen(delimited_product_version)))
    {
        std::cout << "failed to copy product version wstring: " << GetLastError() << std::endl;
        return false;
    }

    *supported = false;

    int svi = 0;
    do {
        if (supported_unity_versions[svi]) {
            if (_wcsicmp(version, supported_unity_versions[svi]) == 0)
                *supported = true;
        }
    } while (supported_unity_versions[++svi]);


    return true;
}

static bool on_unityplayer_load(HANDLE process, uintptr_t image_base, wchar_t* image_path) {
    section_info    sinfo{};
    uintptr_t       patch_instruction = 0;
    wchar_t         unity_version[128]{};
    bool            version_supported = false;

    std::cout << "loaded unityplayer: " << std::hex << image_base << std::endl;

    if (!unityplayer_version_supported(image_path, &version_supported, unity_version)) {
        std::cout << "failed to obtain unity support: " << GetLastError();
        return false;
    }

    std::wcout << L"unity version: " << unity_version << std::endl;
    if (!version_supported)
    {
        std::cout << "unsupported unity version detected, this will likely fail" << std::endl;
        std::cout << "would you like to continue (y/n)?: ";
        char choice = (char)std::cin.get();
        if (choice == 'N' || choice == 'n')
            return false;
    }
    else
        std::cout << "unity version supported" << std::endl;

    if (!get_image_section_info(process, image_base, ".text", &sinfo)) {
        std::cout << "failed to get text section info: " << GetLastError() << std::endl;
        return false;
    }

    std::cout << "text section base: " << sinfo.base << std::endl;
    std::cout << "text section size: " << sinfo.size << std::endl;

    patch_instruction = sig_scan(process, sinfo.base, sinfo.size, "40 55 57 41 54 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 33 FF");
    if (!patch_instruction) {
        std::cout << "signature scan invalid: " << GetLastError() << std::endl;
        return false;
    }
    patch_instruction += 0x68A;
    std::cout << "instruction: " << patch_instruction << std::endl;

    // Skip other instance force close
    char patch_jmp[1] = { '\xEB' };
    // jz -> jmp
    wpm(process, patch_instruction, patch_jmp, sizeof(patch_jmp));
    std::cout << "patched jmp" << std::endl;

    patch_instruction = patch_instruction + 0x9E;

    // Parse CMD line = 1
    // xor eax, eax
    // inc eax
    char patch_retn_value[4] = { '\x31', '\xC0', '\xFF', '\xC0' };
    wpm(process, patch_instruction, patch_retn_value, sizeof(patch_retn_value));
    std::cout << "patched retn value" << std::endl;

    std::cout << "finished patches returning to debug event" << std::endl;

    return true;
}

int main(int argc, char** argv) {
    char*               image_path = 0;
    uintptr_t           image_base = 0;
    STARTUPINFOA        si{};
    PROCESS_INFORMATION pi{};
    char                full_image_path[MAX_PATH]{};

    if (argc != 2)
    {
        print_usage();
        return 1;
    }

    image_path = argv[1];

    if (!GetFullPathNameA(image_path, MAX_PATH, full_image_path, 0)) {
        std::cout << "failed to get full path name of file: " << GetLastError() << std::endl;
        return 2;
    }
    std::cout << "full path:  " << full_image_path << std::endl;

    if (!CreateProcessA(full_image_path, nullptr, nullptr, nullptr, false, DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi))
    {
        std::cout << "process creation failed: " << GetLastError() << std::endl;
        return 3;
    }
    std::cout << "created process: " << std::dec << pi.dwProcessId << std::endl;

    if (!wait_for_module_load(pi, L"UnityPlayer.dll", on_unityplayer_load)) {
        std::cout << "failed to wait for module load: " << GetLastError() << std::endl;
        return 4;
    }

    std::cout << "done, execution resumed" << std::endl;

    std::cout << "cleaning up..." << std::endl;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    std::cout << "finished" << std::endl;
    return 0;
}