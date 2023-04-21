/*++

Module Name:

    public.h

Abstract:

    This module contains the common declarations shared by driver
    and user applications.

Environment:

    user and kernel

--*/

//
// Define an Interface Guid so that apps can find the device and talk to it.
//

DEFINE_GUID (GUID_DEVINTERFACE_RootKitDriver,
    0xd494338b,0x13bd,0x48ea,0xb6,0x70,0x4f,0x22,0xe7,0xae,0xdf,0xc0);
// {d494338b-13bd-48ea-b670-4f22e7aedfc0}
