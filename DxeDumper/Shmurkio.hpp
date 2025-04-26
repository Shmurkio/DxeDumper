#pragma warning(disable : 4201)
#pragma warning(disable : 4083)
#pragma warning(disable : 4005)
#pragma warning(disable : 4200)

#pragma once

#include <ntddk.h>
#include <cstdint>

#include "Util.hpp"

#define EFI_VARIABLE_NON_VOLATILE        0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS  0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS      0x00000004

typedef UINT64 UINTN;
typedef UINTN RETURN_STATUS;
typedef RETURN_STATUS EFI_STATUS;

typedef struct _HAL_EFI_RUNTIME_SERVICES_TABLE
{
	PVOID GetTime;
	PVOID SetTime;
	PVOID ResetSystem;
	PVOID GetVariable;
	PVOID GetNextVariableName;
	PVOID SetVariable;
	PVOID UpdateCapsule;
	PVOID QueryCapsuleCapabilities;
	PVOID QueryVariableInfo;
} HAL_EFI_RUNTIME_SERVICES_TABLE, *PHAL_EFI_RUNTIME_SERVICES_TABLE;