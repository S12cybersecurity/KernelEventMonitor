#include <ntddk.h>
#include <wdf.h>

void ownCreateProcessNotifyRoutine(HANDLE ppid, HANDLE pid, BOOLEAN create){
	UNREFERENCED_PARAMETER(ppid);
	UNREFERENCED_PARAMETER(pid);
	UNREFERENCED_PARAMETER(create);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CreateProcessNotifyRoutine: %s process %d\n", create ? "Create" : "Terminate", pid);
}

void ownCreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create) {
	UNREFERENCED_PARAMETER(pid);
	UNREFERENCED_PARAMETER(tid);
	UNREFERENCED_PARAMETER(create);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CreateThreadNotifyRoutine: %s thread %d in process %d\n", create ? "Create" : "Terminate", tid, pid);
}

void ownLoadImageNotifyRoutine(PUNICODE_STRING fullImageName, HANDLE processId, PIMAGE_INFO imageInfo) {
	UNREFERENCED_PARAMETER(processId);
	UNREFERENCED_PARAMETER(imageInfo);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "LoadImageNotifyRoutine: %wZ loaded into process %d\n", fullImageName, processId);
}

VOID UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symbolicLinkName;
	RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\EventMonitor");
	IoDeleteSymbolicLink(&symbolicLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	// Create a device object
	UNICODE_STRING deviceName;
	RtlInitUnicodeString(&deviceName, L"\\Device\\EventMonitor");
	PDEVICE_OBJECT deviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create device object (0x%08X)\n", status);
		return status;
	}

	// Create a symbolic link
	UNICODE_STRING symbolicLinkName;
	RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\EventMonitor");
	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(deviceObject);
		return status;
	}

    DriverObject->DriverUnload = UnloadDriver;
    //DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;
    //DriverObject->MajorFunction[IRP_MJ_READ] = IrpReadHandler;

	// suscribe to the process creation/termination event
	NTSTATUS result = PsSetCreateProcessNotifyRoutine(ownCreateProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(result)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to set CreateProcessNotifyRoutine (0x%08X)\n", result);
		return result;
	}

	NTSTATUS resultThread = PsSetCreateThreadNotifyRoutine(ownCreateThreadNotifyRoutine);
	if (!NT_SUCCESS(resultThread)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to set CreateThreadNotifyRoutine (0x%08X)\n", resultThread);
		return resultThread;
	}

	NTSTATUS moduleResult = PsSetLoadImageNotifyRoutine(ownLoadImageNotifyRoutine);
	if (!NT_SUCCESS(moduleResult)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to set LoadImageNotifyRoutine (0x%08X)\n", moduleResult);
		return moduleResult;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver loaded and started\n");


    return STATUS_SUCCESS;
}

