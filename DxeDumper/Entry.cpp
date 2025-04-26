#include "Shmurkio.hpp"

extern "C"
VOID
DriverUnload(
    [[maybe_unused]] _In_ PDRIVER_OBJECT DriverObject
)
{
    //DbgPrintEx(0, 0, "Driver unloaded!\n");
}

extern "C"
NTSTATUS
DriverEntry(
    [[maybe_unused]] _In_ PDRIVER_OBJECT DriverObject,
    [[maybe_unused]] _In_ PUNICODE_STRING RegistryPath
)
{
    DriverObject->DriverUnload = DriverUnload;
    
    //
    // We need ntoskrnl base to find HalEfiRuntimeServicesTable.
    //
    PLDR_DATA_TABLE_ENTRY Kernel = nullptr;
    NTSTATUS Status = Util::GetModuleByName("ntoskrnl.exe", Kernel);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "ntoskrnl.exe not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "ntoskrnl.exe: 0x%p\n", Kernel);

    //
    // Find HalEfiRuntimeServicesTable.
    //
    PHAL_EFI_RUNTIME_SERVICES_TABLE HalEfiRuntimeServicesTable = reinterpret_cast<PHAL_EFI_RUNTIME_SERVICES_TABLE>(reinterpret_cast<uint64_t>(Kernel->DllBase) + 0xE01870);

    if (!HalEfiRuntimeServicesTable)
    {
        DbgPrintEx(0, 0, "HalEfiRuntimeServicesTable not found\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrintEx(0, 0, "HalEfiRuntimeServicesTable: 0x%p\n", HalEfiRuntimeServicesTable);

    //
    // Retrieve EFI runtime functions to dump their appropriate DXE driver.
    // NVRAM DXE driver.
    //
    if (!HalEfiRuntimeServicesTable->SetVariable)
    {
        DbgPrintEx(0, 0, "EfiSetVariable not found\n");
        return STATUS_NOT_FOUND;
    }

    void* DriverBase = nullptr;
    Status = Util::GetImageBase(reinterpret_cast<void*>(HalEfiRuntimeServicesTable->SetVariable), DriverBase);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "NVRAM DXE driver not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "NVRAM DXE driver: 0x%p\n", DriverBase);

    size_t DriverSize = 0;
    Status = Util::GetImageSize(DriverBase, DriverSize);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "NVRAM DXE driver size not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "NVRAM DXE driver size: %llu\n", DriverSize);

    Status = Util::DumpMemoryToFile(DriverBase, DriverSize, L"\\??\\C:\\NvramDxe.efi");

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Failed to dump NVRAM DXE driver: 0x%lX\n", Status);
        return Status;
    }

    //
    // RTC DXE driver.
    //
    if (!HalEfiRuntimeServicesTable->SetTime)
    {
        DbgPrintEx(0, 0, "EfiSetTime not found\n");
        return STATUS_NOT_FOUND;
    }

    DriverBase = nullptr;
    Status = Util::GetImageBase(reinterpret_cast<void*>(HalEfiRuntimeServicesTable->SetTime), DriverBase);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "RTC DXE driver not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "RTC DXE driver: 0x%p\n", DriverBase);

    DriverSize = 0;
    Status = Util::GetImageSize(DriverBase, DriverSize);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "RTC DXE driver size not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "RTC DXE driver size: %llu\n", DriverSize);

    Status = Util::DumpMemoryToFile(DriverBase, DriverSize, L"\\??\\C:\\RtcDxe.efi");

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Failed to dump RTC DXE driver: 0x%lX\n", Status);
        return Status;
    }

    //
    // Reset System DXE driver.
    //
    if (!HalEfiRuntimeServicesTable->ResetSystem)
    {
        DbgPrintEx(0, 0, "EfiResetSystem not found\n");
        return STATUS_NOT_FOUND;
    }

    DriverBase = nullptr;
    Status = Util::GetImageBase(reinterpret_cast<void*>(HalEfiRuntimeServicesTable->ResetSystem), DriverBase);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Reset System DXE driver not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "Reset System DXE driver: 0x%p\n", DriverBase);

    DriverSize = 0;
    Status = Util::GetImageSize(DriverBase, DriverSize);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Reset System DXE driver size not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "Reset System DXE driver size: %llu\n", DriverSize);

    Status = Util::DumpMemoryToFile(DriverBase, DriverSize, L"\\??\\C:\\ResetSystemDxe.efi");

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Failed to dump Reset System DXE driver: 0x%lX\n", Status);
        return Status;
    }

    //
    // Capsule Runtime DXE driver.
    //
    if (!HalEfiRuntimeServicesTable->UpdateCapsule)
    {
        DbgPrintEx(0, 0, "EfiUpdateCapsule not found\n");
        return STATUS_NOT_FOUND;
    }

    DriverBase = nullptr;
    Status = Util::GetImageBase(reinterpret_cast<void*>(HalEfiRuntimeServicesTable->UpdateCapsule), DriverBase);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Runtime Capsule DXE driver not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "Runtime Capsule DXE driver: 0x%p\n", DriverBase);

    DriverSize = 0;
    Status = Util::GetImageSize(DriverBase, DriverSize);

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Runtime Capsule DXE driver size not found\n");
        return Status;
    }

    DbgPrintEx(0, 0, "Runtime Capsule DXE driver size: %llu\n", DriverSize);

    Status = Util::DumpMemoryToFile(DriverBase, DriverSize, L"\\??\\C:\\RuntimeCapsuleDxe.efi");

    if (!NT_SUCCESS(Status))
    {
        DbgPrintEx(0, 0, "Failed to dump Runtime Capsule DXE driver: 0x%lX\n", Status);
        return Status;
    }

    return Status;
}