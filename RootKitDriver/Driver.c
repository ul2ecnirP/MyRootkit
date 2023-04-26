#include <ntddk.h>
#include <wdf.h>
#pragma warning (disable : 4702 4996 4100)

DRIVER_INITIALIZE DriverEntry;


void OnUnload(IN PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(0, 0, "Bye Bye !!!\n");
}
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){
    // NTSTATUS variable to record success or failure
    DbgPrintEx(0, 0, "Hey from kernel ! now hacking...\n");
    DriverObject->DriverUnload = OnUnload;
    return STATUS_SUCCESS;
}

