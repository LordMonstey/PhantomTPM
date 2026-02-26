#pragma once

namespace Spoofer
{
	extern PDRIVER_DISPATCH OriginalDeviceControl;
	extern TPM2B_PUBLIC_KEY_RSA SpoofedKey;

	NTSTATUS CompletionRoutinePublic(PDEVICE_OBJECT device, PIRP irp, PVOID context);
	NTSTATUS CompletionRoutineNv(PDEVICE_OBJECT device, PIRP irp, PVOID context);
	NTSTATUS InterceptDeviceControl(PDEVICE_OBJECT device, PIRP irp);
	bool ExecuteHook(PDRIVER_OBJECT driverObject);
}