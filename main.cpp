#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <comdef.h>
#include <vector>

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

    const WORD numberOfSections = nt_leader.fileheader.NumberOfSections;
    const WORD sizeOfOptional = nt_leader.fileheader.SizeOfOptionalHeader;

    const uintptr_t sections_addr =
        nt_addr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + static_cast<uintptr_t>(sizeOfOptional);

    for (WORD i = 0; i < numberOfSections; ++i) {
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
    constexpr size_t chunk_size = 0x10000;
    size_t bytes_read = 0;

    std::vector<uint8_t> buffer(chunk_size);

    while (bytes_read < size) {
        size_t to_read = (size - bytes_read < chunk_size) ? (size - bytes_read) : chunk_size;

        if (!rpm(process, module_base + bytes_read, buffer.data(), to_read))
            return 0; 

        for (size_t i = 0; i < to_read; i++) {
            if (match_signature(&buffer[i], signature)) {
                return module_base + bytes_read + i; 
            }
        }

        bytes_read += to_read;
    }

    return 0; 
}

using t_on_image_loaded = void(*)(HANDLE h, uintptr_t);

static bool wait_for_module_load(PROCESS_INFORMATION pi, const wchar_t* mod_name, t_on_image_loaded on_load) {
    DEBUG_EVENT         dbg                         {};
    uintptr_t           module_base                 = 0;
    wchar_t             module_name[MAX_PATH]       {};
    bool                found                       = false;

    while (WaitForDebugEvent(&dbg, INFINITE)) {
        switch (dbg.dwDebugEventCode) {

        case LOAD_DLL_DEBUG_EVENT: {
            auto& ev = dbg.u.LoadDll;
            uintptr_t base = reinterpret_cast<uintptr_t>(ev.lpBaseOfDll);

            std::wstring module_name;

            if (ev.lpImageName && ev.fUnicode) {
                LPVOID remote_buffer = nullptr;

                if (rpm(pi.hProcess, (uintptr_t)ev.lpImageName, &remote_buffer, sizeof(remote_buffer)) && remote_buffer) {
                    wchar_t buf[MAX_PATH] = {};

                    if (rpm(pi.hProcess, (uintptr_t)remote_buffer, buf, sizeof(buf))) {
                        module_name = buf;
                    }
                }
            }

            if (module_name.find(mod_name) != std::string::npos) {
                on_load(pi.hProcess, base);
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

static void on_unityplayer_load(HANDLE process, uintptr_t image_base) {
    section_info        sinfo                   {};
    uintptr_t           patch_instruction =     0;

    std::cout << "loaded unityplayer: " << std::hex << image_base << std::endl;

    if (!get_image_section_info(process, image_base, ".text", &sinfo)) {
        std::cout << "failed to get text section info: " << GetLastError() << std::endl;
        return;
    }

    std::cout << "text section base: " << sinfo.base << std::endl;
    std::cout << "text section size: " << sinfo.size << std::endl;

    patch_instruction = sig_scan(process, sinfo.base, sinfo.size, "48 8B DF 48 89 1D ?? ?? ?? ?? 40 38 7D ?? 75 ?? 44 8B 45 ?? 48 8B 55 ?? 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 1D ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ?? 0F B6 F0 84 C0 74 ?? 48 8B CB E8 ?? ?? ?? ?? 84 C0 0F 84 ?? ?? ?? ?? 40 84 F6 0F 94 C3");
    if (!patch_instruction) {
        std::cout << "signature scan invalid: " << GetLastError() << std::endl;
        return;
    }
    patch_instruction += 0x38;
    std::cout << "instruction: " << patch_instruction << std::endl;
    
    // Skip other instance force close
    char patch[1] = { '\xEB' };
    // jz -> jmp
    wpm(process, patch_instruction, patch, sizeof(patch));
    std::cout << "patch 1 finished" << std::endl;

    patch_instruction = patch_instruction + 0x9E;

    // Parse CMD line = 1
    // xor eax, eax
    // inc eax
    char patch2[4] = { '\x31', '\xC0', '\xFF', '\xC0' }; 
    wpm(process, patch_instruction, patch2, sizeof(patch2));
    std::cout << "patch 2 finished" << std::endl;

    std::cout << "finished patches returning to debug event" << std::endl;
}

int main(int argc, char** argv) {
    char*               image_path                  = 0;
    uintptr_t           image_base                  = 0;
    STARTUPINFOA        si                          {};
    PROCESS_INFORMATION pi                          {};
    char                full_image_path[MAX_PATH]   {};

	if (argc <= 1 || argc >= 3)
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
    std::cout << "created process:  " << std::dec << pi.dwProcessId << std::endl;

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