#include "pch.h"
#include <windows.h>
#include <tlhelp32.h>
#include <shellapi.h>
#include <iostream>

// Fungsi untuk memeriksa apakah aplikasi tertentu sedang berjalan
bool IsProcessRunning(const wchar_t* processName) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return false;

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hProcessSnap);
                return true;
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return false;
}

// Fungsi untuk menangguhkan (suspend) semua thread dalam sebuah proses
void SuspendAllThreads(DWORD processID) {
    HANDLE hThreadSnap;
    THREADENTRY32 te32;
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return;

    te32.dwSize = sizeof(THREADENTRY32);

    // Iterasi semua thread yang ada di sistem
    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processID) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread != NULL) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
}

// Fungsi untuk mendeteksi berbagai aplikasi reverse engineering dan Task Manager
void TerminateLostSagaIfReverseEngAppsDetected() {
    // Daftar aplikasi reverse engineering yang harus dideteksi
    const wchar_t* reverseEngApps[] = {
        L"Taskmgr.exe",   // Task Manager
        L"cheatengine-x86_64-SSE4-AVX2.exe",   // Cheat Engine x64
        L"cheatengine-i386.exe",   // Cheat Engine x32
        L"cheatengine-x86_64.exe",   // Cheat Engine x86_64
        L"ida.exe",      // IDA Pro
        L"ida64.exe",      // IDA Pro
        L"ida64.exe",      // IDA Pro
        L"ollydbg.exe",   // OllyDbg
        L"x64dbg.exe",    // x64dbg
        L"windbg.exe"     // WinDbg
        L"ProcessHacker.exe"     // Process Hacker
    };

    // Memeriksa apakah aplikasi reverse engineering atau Task Manager sedang berjalan
    for (const wchar_t* appName : reverseEngApps) {
        if (IsProcessRunning(appName)) {
            PROCESSENTRY32 pe32;
            HANDLE hProcessSnap;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hProcessSnap == INVALID_HANDLE_VALUE)
                return;

            if (Process32First(hProcessSnap, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, L"lostsaga.exe") == 0) {
                        HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                        if (hProcess != NULL) {
                            // Menangguhkan seluruh thread dalam proses lostsaga.exe
                            SuspendAllThreads(pe32.th32ProcessID);

                            // Menampilkan notifikasi warning bahwa aplikasi reverse engineering terdeteksi
                            int result = MessageBox(NULL, L"Thread Detection!!",
                                L"Astra Vortex", MB_OK | MB_ICONWARNING);

                            if (result == IDOK) {
                                TerminateProcess(hProcess, 0);
                                MessageBox(NULL, L"LostSaga.exe Terminate!.", L"Astra Vortex", MB_OK | MB_ICONINFORMATION);
                            }

                            CloseHandle(hProcess);
                        }
                    }
                } while (Process32Next(hProcessSnap, &pe32));
            }

            CloseHandle(hProcessSnap);
            return;  // Jika salah satu aplikasi terdeteksi, hentikan pemeriksaan lebih lanjut
        }
    }
}

// Thread untuk memantau aplikasi reverse engineering
DWORD WINAPI MonitorReverseEngApps(LPVOID lpParam) {
    while (true) {
        TerminateLostSagaIfReverseEngAppsDetected();
        Sleep(1000); // Cek setiap detik
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Membuat thread untuk memonitor aplikasi reverse engineering
        CreateThread(NULL, 0, MonitorReverseEngApps, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
