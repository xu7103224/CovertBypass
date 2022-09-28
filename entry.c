#include "types.h"

#include "bypass.h"

void DriverUnload(DRIVER_OBJECT* driver) {
	bypass_cleanup();

	DbgPrint("[Covert Bypass]: Unloaded. \n");
}

NTSTATUS DriverClose(IN DEVICE_OBJECT* device, IN IRP* irp) {
	UNREFERENCED_PARAMETER(device);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	DbgPrint("[Covert Bypass]: Closed. \n");

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(DRIVER_OBJECT* driver, PUNICODE_STRING registry_path) {
	driver->MajorFunction[IRP_MJ_CLOSE] = &DriverClose;
	driver->DriverUnload                = &DriverUnload;

	if (!bypass_initialize(driver)) return STATUS_FAILED_DRIVER_ENTRY;

	return STATUS_SUCCESS;
}