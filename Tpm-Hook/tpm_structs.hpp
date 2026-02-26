#pragma once

#define IOCTL_TPM_SUBMIT_COMMAND 0x22C00C

#pragma pack(push, 1)
typedef struct _TPM_DATA_READ_PUBLIC
{
	TPM2_RESPONSE_HEADER Header;
	TPM2B_PUBLIC OutPublic;
} TPM_DATA_READ_PUBLIC;

typedef struct _TPM_DATA_NV_READ
{
	TPM2_RESPONSE_HEADER Header;
	UINT32 parameterSize;
	UINT16 dataSize;
	BYTE data[1];
} TPM_DATA_NV_READ;
#pragma pack(pop)