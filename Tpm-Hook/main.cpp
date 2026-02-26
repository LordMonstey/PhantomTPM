#include "includes.hpp"

EXTERN_C NTSTATUS Entry(PVOID mapped_base, PVOID reserved)
{
	UNREFERENCED_PARAMETER(mapped_base);
	UNREFERENCED_PARAMETER(reserved);

	NTSTATUS status = Mem::CreateSpoofedKey(&Spoofer::SpoofedKey);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	UNICODE_STRING driverName;
	RtlInitUnicodeString(&driverName, L"\\Driver\\TPM");

	PDRIVER_OBJECT driverObject;
	status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, nullptr, 0,
		*IoDriverObjectType, KernelMode, nullptr,
		reinterpret_cast<PVOID*>(&driverObject));

	if (!NT_SUCCESS(status))
		return status;

	if (!Spoofer::ExecuteHook(driverObject))
	{
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}