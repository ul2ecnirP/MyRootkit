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
#include "resource.h"
#include "mdmain.h"

PEB* RtlGetCurrentPeb(VOID)
{
    return NtCurrentTeb()->ProcessEnvironmentBlock;
}

PVOID SelfGetModuleHandle(uint8_t name[16]) {

    PEB* pPeb = RtlGetCurrentPeb();
    PPEB_LDR_DATA pLdr = pPeb->Ldr;
    PLIST_ENTRY current = pPeb->Ldr->InMemoryOrderModuleList.Flink;
    uint8_t* result = malloc(16);
    while ((current != NULL) && (current != &pPeb->Ldr->InMemoryOrderModuleList))//stackoverflow modification
    {
        LDR_DATA_TABLE_ENTRY* module = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);//stackoverflow modification
        wmd5String((wcsrchr(module->FullDllName.Buffer, L'\\') + 1), result);
        if (memcmp(result, name, 16)) {
            printf("Base found !!!\n");
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
typedef
HRSRC 
(__stdcall* FINDRESSOURCEA)(
    HMODULE hModule,
    LPCSTR  lpName,
    LPCSTR  lpType
);
typedef
HGLOBAL 
(__stdcall* LOADRESSOURCE)(
    HMODULE hModule,
    HRSRC   hResInfo
);
typedef
DWORD 
(__stdcall* SIZEOFRESSOURCE)(
    HMODULE hModule,
    HRSRC   hResInfo
);
typedef 
LPVOID 
(__stdcall* LOCKRESSOURCE)(
    HGLOBAL hResData
);
int main() {
    
    uint8_t data[16] = { 0xa3,0xcb,0x33,0x79,0xad,0xcf,0x19,0x3f,0xae,0x75,0xca,0x47,0x18,0x6c,0x02 };

    HMODULE ntdllBase = (HMODULE)SelfGetModuleHandle(data);
    
    wchar_t* wstring = L"ntdll.dll";
    printf("\nntdll:\n");
    uint8_t *result = malloc(16);
    wmd5String(wstring, result);
    for (size_t i = 0; i < 16; i++)
    {
        printf("%x", result[i]);
    }

    //HMODULE kerneldllBase = (HMODULE)SelfGetModuleHandle(data);
    //if (kerneldllBase == NULL) {
    //    printf("Error Kernel32.dll doesnt exist");
    //    return 1;
    //}
    /*
    if (ntdllBase == NULL) {
        printf("Error %p\n", ntdllBase);
    }
    else {
        POW pow = (POW)SelfGetProcAddress(ntdllBase, "pow");
        printf("%f\n", pow(2.0, 3.0));
    }
    */
    /*
    FINDRESSOURCEA FindResourceW_ = (FINDRESSOURCEA)SelfGetProcAddress(kerneldllBase, "FindResourceW");
    HRSRC BmpRessource = FindResourceW_(NULL, MAKEINTRESOURCE(IDB_BITMAP1), MAKEINTRESOURCE(2));

    LOADRESSOURCE LoadResource_ = (LOADRESSOURCE)SelfGetProcAddress(kerneldllBase, "LoadResource");
    HGLOBAL GlobalRessource = LoadResource_(NULL, BmpRessource);
    if (!GlobalRessource) {
        printf("Global Ressource Error !!!");
        return 1;
    }
    SIZEOFRESSOURCE SizeofRessource_ = (SIZEOFRESSOURCE)SelfGetProcAddress(kerneldllBase, "SizeofResource");
    size_t FileSize = SizeofRessource_(NULL, BmpRessource);
    LOCKRESSOURCE LockResource_ = (LOCKRESSOURCE)SelfGetProcAddress(kerneldllBase, "LockResource");
    uint8_t* FilePtr = (uint8_t*)LockResource_(GlobalRessource);
    for (size_t i = 0; i < FileSize; i++)
    {
        printf("%x", FilePtr[i]);
    }*/

    /*
    char* data = "Salut!";
    uint8_t *result = malloc(16);
    md5String(data, result);
    for (size_t i = 0; i < 16; i++)
    {
        printf("%x", result[i]);
    }
    */
    printf("\nFinish !\n");
    //SYSTEM_LOAD_AND_CALL_IMAGE Image;
    //WCHAR mypath[] = L"./driver.sys";
    //RTLINITUNICODESTRING RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString");
    //ZWSETSYSTEMINFORMATION ZwSetSystemInformation = (ZWSETSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSetSystemInformation");
    //RtlInitUnicodeString(&Image.ModuleName, mypath);
    //ZwSetSystemInformation(38, &Image,sizeof(SYSTEM_LOAD_AND_CALL_IMAGE));
    return 1;
}