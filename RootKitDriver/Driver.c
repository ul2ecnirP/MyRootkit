#include <ntddk.h>
#include <wdf.h>
#pragma warning (disable : 4702 4996 4100)

DRIVER_INITIALIZE DriverEntry;



NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,_In_ PUNICODE_STRING RegistryPath){
    // NTSTATUS variable to record success or failure
    DbgPrintEx(0, 0, "Hey from kernel !\n");
    return STATUS_SUCCESS;
}

