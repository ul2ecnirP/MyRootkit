
#include <ntddk.h>
#include <wdf.h>


#pragma warning (disable : 4100 )

DRIVER_INITIALIZE DriverEntry;

typedef unsigned long       DWORD;

void OnUnload(IN PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(0, 0, "Bye Bye !!!\n");
}
//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm
//Windows NT PID offset:0x94
//Windows NT Flink offset:0x98
int HideProcess(int targetPID) {
    PEPROCESS process = IoGetCurrentProcess();
    NTSTATUS status = 0;
    LIST_ENTRY ActiveProcessLinks;
    ActiveProcessLinks = *((LIST_ENTRY*)process + 0x448);

    
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){
    // NTSTATUS variable to record success or failure
    DbgPrintEx(0, 0, "Hey from kernel ! now testing goofy ahh tables...\n");
    DriverObject->DriverUnload = OnUnload;
    HideProcess(0);//nothing

    return STATUS_SUCCESS;
}