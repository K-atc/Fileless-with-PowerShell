/* spy.c */
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32")
#define EXPORT extern "C" __declspec(dllexport)

// EXPORT VOID DisplayHello()
// {
//     MessageBox(NULL, "Hello!", "Hello", MB_SYSTEMMODAL);
// }

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char filename[MAX_PATH];

    switch (fdwReason) {
      case DLL_PROCESS_ATTACH:
        GetModuleFileName(NULL, filename, sizeof(filename));
        MessageBox(NULL, filename, "[DLL_PROCESS_ATTACH] Hello from", MB_SYSTEMMODAL);
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        fprintf(stdout, "Welcome to STDOUT\n");
        break;
      case DLL_THREAD_ATTACH:
        GetModuleFileName(NULL, filename, sizeof(filename));
        MessageBox(NULL, filename, "[DLL_THREAD_ATTACH] Hello from", MB_SYSTEMMODAL);
        fprintf(stdout, "Welcome to STDOUT\n");
        break;
    }
    return TRUE;
}

// compile:
// cl spy.c /LD
// compile for x86_64:
// vcvarsall amd64_x86
// cl spy.c /LD /Fe:spy_x86.dll