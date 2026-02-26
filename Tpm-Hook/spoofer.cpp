#include "includes.hpp"

#ifndef TPM_CC_NV_Read
#define TPM_CC_NV_Read 0x0000014E
#endif

TPM2B_PUBLIC_KEY_RSA Spoofer::SpoofedKey = { 0 };
PDRIVER_DISPATCH Spoofer::OriginalDeviceControl = nullptr;

NTSTATUS Spoofer::CompletionRoutinePublic(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(irp);

	if (!context)
		return STATUS_SUCCESS;

	Mem::IOC_REQUEST request = *static_cast<Mem::PIOC_REQUEST>(context);
	Mem::Free(context);

	TPM_DATA_READ_PUBLIC* data = static_cast<TPM_DATA_READ_PUBLIC*>(request.Buffer);

	const UINT32 commandSize = Mem::SwapEndian32(data->Header.paramSize);
	const size_t keySize = 128;
	const size_t minSize = offsetof(TPM_DATA_READ_PUBLIC, OutPublic.publicArea.unique.rsa.buffer) + keySize;

	if (commandSize < minSize)
	{
		return STATUS_SUCCESS;
	}

	memcpy(data->OutPublic.publicArea.unique.rsa.buffer, SpoofedKey.buffer, keySize);

	return STATUS_SUCCESS;
}

NTSTATUS Spoofer::CompletionRoutineNv(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(device);
	UNREFERENCED_PARAMETER(irp);

	if (!context)
		return STATUS_SUCCESS;

	Mem::IOC_REQUEST request = *static_cast<Mem::PIOC_REQUEST>(context);
	Mem::Free(context);

	TPM_DATA_NV_READ* data = static_cast<TPM_DATA_NV_READ*>(request.Buffer);

	const UINT32 commandSize = Mem::SwapEndian32(data->Header.paramSize);

	if (commandSize > sizeof(TPM2_RESPONSE_HEADER) + sizeof(UINT32) + sizeof(UINT16))
	{
		UINT16 nvSize = Mem::SwapEndian16(data->dataSize);
		if (nvSize > 0)
		{
			memset(data->data, 0, nvSize);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS Spoofer::InterceptDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
	const PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);

	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_TPM_SUBMIT_COMMAND)
	{
		const TPM2_COMMAND_HEADER* header = static_cast<TPM2_COMMAND_HEADER*>(irp->AssociatedIrp.SystemBuffer);
		const TPM_CC command = Mem::SwapEndian32(header->commandCode);

		if (command == TPM_CC_ReadPublic)
		{
			Mem::ModifyIoc(ioc, irp, &CompletionRoutinePublic);
		}
		else if (command == TPM_CC_NV_Read)
		{
			Mem::ModifyIoc(ioc, irp, &CompletionRoutineNv);
		}
	}

	return OriginalDeviceControl(device, irp);
}

bool Spoofer::ExecuteHook(PDRIVER_OBJECT driverObject)
{
	OriginalDeviceControl = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	PVOID tpmBase = Mem::GetKernelModule("tpm.sys");

	if (!tpmBase)
		return false;

	PVOID codeCave = Mem::FindCodeCave(tpmBase, 12);
	if (!codeCave)
		return false;

	if (!Mem::BuildTrampoline(codeCave, reinterpret_cast<PVOID>(&Spoofer::InterceptDeviceControl)))
		return false;

	PVOID targetAddress = &driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	return Mem::WriteProtectedMemory(targetAddress, &codeCave, sizeof(PVOID));
}