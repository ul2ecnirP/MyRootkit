#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <Windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <psapi.h>
#include <shlobj_core.h>
#include <windows.h>

#pragma comment(lib, "Shlwapi.lib")

#include "implant_rsrc.h"


PEB* RtlGetCurrentPeb(VOID)
{
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

PVOID SelfGetModuleHandle(PCWSTR name) {

    PEB* pPeb = RtlGetCurrentPeb();
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    LIST_ENTRY Lentry = pLdr->InMemoryOrderModuleList;
    PLIST_ENTRY current = pPeb->Ldr->InMemoryOrderModuleList.Flink;
    while ((current != NULL) && (current != &pPeb->Ldr->InMemoryOrderModuleList))//stackoverflow modification
    {
        LDR_DATA_TABLE_ENTRY* module = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);//stackoverflow modification
        if (StrCmpW((wcsrchr(module->FullDllName.Buffer, L'\\') + 1), name) == 0) {
            return module->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}
PVOID SelfGetProcAddress(HMODULE module, PCWSTR name) {
    //module = LoadLibraryEx("ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE*)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

}

typedef
double
(__stdcall* POW)(
    double a,
    double b
    );


int main() {

    HMODULE dllBase = (HMODULE)SelfGetModuleHandle(L"ntdll.dll");
    if (dllBase == NULL) {
        printf("Error %p\n", dllBase);
    }
    else {
        POW pow = (POW)GetProcAddress(dllBase, "pow");
        printf("%f\n", pow(2.0, 3.0));
    }
    printf("\nFinish !\n");
    SelfGetProcAddress(dllBase, "test");
    //SYSTEM_LOAD_AND_CALL_IMAGE Image;
    //WCHAR mypath[] = L"./driver.sys";
    //RTLINITUNICODESTRING RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    //ZWSETSYSTEMINFORMATION ZwSetSystemInformation = (ZWSETSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetSystemInformation");
    //RtlInitUnicodeString(&Image.ModuleName, mypath);
    //ZwSetSystemInformation(38, &Image,sizeof(SYSTEM_LOAD_AND_CALL_IMAGE));
    return 1;
}