
#include <ntifs.h>

#include <ntddk.h>
#include <wdf.h>
#include <stdlib.h>

int HideProcess(int targetPID);
int GetImageFileNameOffset(char* name);
int SearchAndRemoveEPROCESSbyOffset(int offset, char* target);
DRIVER_INITIALIZE DriverEntry;


#pragma warning (disable : 4100 4201 6387 6011 4996 4311 4152)
typedef struct _EX_FAST_REF
{
    union
    {
        PVOID Object;
        ULONG RefCnt : 3;
        ULONG Value;
    };
} EX_FAST_REF, * PEX_FAST_REF;

//https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
typedef unsigned short WORD, * PWORD, * LPWORD;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
