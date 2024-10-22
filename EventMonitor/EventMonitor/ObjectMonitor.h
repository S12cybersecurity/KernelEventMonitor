#include <ntddk.h>
#include <wdf.h>

PVOID callbackRegistrationHandle = NULL;

OB_PREOP_CALLBACK_STATUS CreateCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);

    PEPROCESS Process = (PEPROCESS)OperationInformation->Object;

    HANDLE pid = PsGetProcessId(Process);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "CreateCallback called with operation %d on process at address %p with PID %d\n",
        OperationInformation->Operation,
        Process,    
        pid         
    );

    return OB_PREOP_SUCCESS;
}


NTSTATUS createRegistration() {
    OB_CALLBACK_REGISTRATION registrationInfo;
    OB_OPERATION_REGISTRATION operationInfo;
    NTSTATUS status;

    RtlZeroMemory(&registrationInfo, sizeof(registrationInfo));
    RtlZeroMemory(&operationInfo, sizeof(operationInfo));

    operationInfo.ObjectType = PsProcessType;
    operationInfo.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationInfo.PreOperation = CreateCallback;

    registrationInfo.Version = OB_FLT_REGISTRATION_VERSION;
    registrationInfo.OperationRegistrationCount = 1;
    registrationInfo.RegistrationContext = NULL;
    registrationInfo.OperationRegistration = &operationInfo;

    status = ObRegisterCallbacks(&registrationInfo, &callbackRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObRegisterCallbacks failed with status 0x%08X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Registered callback successfully\n");
    return STATUS_SUCCESS;
}