#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
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
PVOID SelfGetProcAddress(HMODULE module, char * name) {
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);//get imageNtHeader from DOS_HEADER (e_lfanew = logical file address) (entire dll relocated)
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeaders->OptionalHeader; //getting closer of Export directory by reading OptionalHeader
    PIMAGE_DATA_DIRECTORY imageDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT/*winnt.h*/]);//first element (index0) of Optional header array is the exort table
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)module + imageDataDirectory->VirtualAddress);//getting the RVA (Relative Virtual Adress)
    /*3 arrays of the same size */
    PDWORD exportAddressTable = (PDWORD)((uint8_t*)module + imageExportDirectory->AddressOfFunctions);//function address ( function rva)
    PWORD /*unsigned short*/ nameOrdinalsPointer = (PWORD)((uint8_t*)module + imageExportDirectory->AddressOfNameOrdinals);//contains the address of the function by the name
    PDWORD exportNamePointerTable = (PDWORD)((uint8_t*)module + imageExportDirectory->AddressOfNames);//pointer to the name 
    for (size_t nameIndex = 0; nameIndex < imageExportDirectory->NumberOfNames; nameIndex++)
    {
        char* exportname = (char*)((uint8_t*)module + exportNamePointerTable[nameIndex]);
        if (strcmp(name, exportname) == 0) {
            DWORD ordinal = nameOrdinalsPointer[nameIndex];
            PDWORD targetFunctionAddress = (PDWORD)((uint8_t*)module + exportAddressTable[ordinal]);
            return targetFunctionAddress;
        }
    }
    return NULL;
}
/*https://res.cloudinary.com/practicaldev/image/fetch/s--sMtYPRHi--/c_limit%2Cf_auto%2Cfl_progressive%2Cq_auto%2Cw_880/https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ahb7ncw4rop0ogid77t2.png
*/
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
        POW pow = (POW)SelfGetProcAddress(dllBase, "pow");
        printf("%f\n", pow(2.0, 3.0));
    }
    //SelfGetProcAddress(dllBase, "pow");
    printf("\nFinish !\n");
    //SYSTEM_LOAD_AND_CALL_IMAGE Image;
    //WCHAR mypath[] = L"./driver.sys";
    //RTLINITUNICODESTRING RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    //ZWSETSYSTEMINFORMATION ZwSetSystemInformation = (ZWSETSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetSystemInformation");
    //RtlInitUnicodeString(&Image.ModuleName, mypath);
    //ZwSetSystemInformation(38, &Image,sizeof(SYSTEM_LOAD_AND_CALL_IMAGE));
    return 1;
}