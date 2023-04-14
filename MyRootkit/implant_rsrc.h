#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <Windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <psapi.h>
#include <windows.h>


typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE
{
	UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, * PSYSTEM_LOAD_AND_CALL_IMAGE;

typedef
NTSTATUS
(__stdcall* ZWSETSYSTEMINFORMATION)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength
	);

typedef
VOID
(__stdcall* RTLINITUNICODESTRING)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);
NTSTATUS ZwSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength);