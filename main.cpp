#include <Windows.h>
#include <TlHelp32.h>
#include <stdexcept>
#include <iostream>
#include <winternl.h>
#include <cstdint>
#include <malloc.h>
#include <string>

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

struct SYSTEM_HANDLE
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
};

constexpr ULONG SystemHandleInformation = 16;

std::uint32_t get_process_id(const wchar_t* process_name)
{
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{ sizeof(PROCESSENTRY32W) };

    if (Process32First(snapshot, &entry))
    {
        do {
            if (!_wcsicmp(process_name, entry.szExeFile))
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

std::wstring proc_name(DWORD process_id)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{ sizeof(PROCESSENTRY32W) };

    if (Process32First(snapshot, &entry))
    {
        do {
            if (entry.th32ProcessID == process_id)
            {
                CloseHandle(snapshot);
                return entry.szExeFile;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return L"Unknown";
}

static HANDLE retrieve_process_handle(uint64_t target_process_id)
{
    try
    {
        auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
        if (!NtQuerySystemInformation)
            throw std::runtime_error("Failed to resolve NtQuerySystemInformation.");

        NTSTATUS status;
        ULONG handle_info_size = 0x10000;
        auto handle_info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(malloc(handle_info_size));

        while ((status = NtQuerySystemInformation(SystemHandleInformation, handle_info, handle_info_size, nullptr)) == STATUS_INFO_LENGTH_MISMATCH)
        {
            handle_info = reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(realloc(handle_info, handle_info_size *= 2));
        }

        if (!NT_SUCCESS(status))
        {
            free(handle_info);
            throw std::runtime_error("NtQuerySystemInformation failed!");
        }

        for (ULONG i = 0; i < handle_info->HandleCount; i++)
        {
            auto handle = handle_info->Handles[i];
            const auto process_id = handle.ProcessId;

            HANDLE process_handle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, process_id);
            if (!process_handle)
                continue;

            HANDLE dup_handle;
            if (DuplicateHandle(process_handle, reinterpret_cast<HANDLE>(handle.Handle), GetCurrentProcess(), &dup_handle, PROCESS_QUERY_INFORMATION, FALSE, 0))
            {
                if (GetProcessId(dup_handle) == target_process_id)
                {
                    CloseHandle(process_handle);
                    free(handle_info);

                    std::wstring process_name = proc_name(process_id);
                    std::wcout << L"Found handle: 0x" << std::hex << reinterpret_cast<uintptr_t>(dup_handle)
                        << L" from process: " << process_name << std::endl;

                    return dup_handle;
                }
                CloseHandle(dup_handle);
            }
            CloseHandle(process_handle);
        }

        free(handle_info);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return nullptr;
}

int main()
{
    try
    {
        std::uint32_t cs2_process_id = get_process_id(L"cs2.exe");

        if (cs2_process_id == 0)
        {
            std::cerr << "Process cs2.exe not found!" << std::endl;
            return 1;
        }

        HANDLE handle = retrieve_process_handle(cs2_process_id);

        if (handle)
            std::printf("Found handle: 0x%p \n", handle);
        else
            std::printf("Handle not found!\n");

        Sleep(5000);
    }
    catch (const std::exception& e) {
        std::cerr << "Unhandled exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}