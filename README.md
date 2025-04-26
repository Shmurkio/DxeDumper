# DXE Dumper

This kernel driver extracts and dumps UEFI Runtime DXE drivers that are mapped into memory.

## How it works

The Windows kernel internally stores pointers to selected UEFI Runtime Services functions inside the `HalEfiRuntimeServicesTable` structure:

```c++
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
```

These function pointers point to code located within mapped UEFI Runtime DXE drivers.

> DebugView showing mapped DXE driver bases:  
> ![DebugView](https://i.imgur.com/WbAeb90.png)

## Dumping the drivers

The dumper locates the memory bases of the mapped DXE drivers and dumps them into the `C:\` directory.

**Dumped files:**
- `NvramDxe.efi`
- `ResetSystemDxe.efi`
- `RtcDxe.efi`
- `RuntimeCapsuleDxe.efi`

> Dumped DXE drivers:  
> ![Dumped drivers](https://i.imgur.com/NAWvTXF.png)

## Reverse engineering the dumped drivers

You can reverse engineer the dumped `.efi` files using [IDA Pro](https://hex-rays.com/ida-pro/).

I recommend using the IDA plugin [efiXplorer](https://github.com/binarly-io/efiXplorer).

> Viewing a dumped driver in IDA with efiXplorer:
> ![IDA](https://i.imgur.com/rNXsX6J.png)