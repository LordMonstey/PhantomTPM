#pragma once

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemInformationClassMin = 0,
	SystemModuleInformation = 11,
	SystemInformationClassMax
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

extern "C"
{
	NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
	NTSTATUS ObReferenceObjectByName(PUNICODE_STRING objectName, ULONG attributes, PACCESS_STATE accessState, ACCESS_MASK desiredAccess, POBJECT_TYPE objectType, KPROCESSOR_MODE accessMode, PVOID parseContext, PVOID* object);
}

extern "C" POBJECT_TYPE* IoDriverObjectType;

namespace Mem
{
	typedef struct _IOC_REQUEST
	{
		PVOID Buffer;
		ULONG Size;
		PVOID OriginalContext;
		PIO_COMPLETION_ROUTINE Original;
	} IOC_REQUEST, * PIOC_REQUEST;

	PVOID Allocate(SIZE_T size);
	void Free(PVOID memory);

	char* StringCompare(const char* haystack, const char* needle);
	PVOID GetKernelModule(const char* moduleName);

	bool WriteProtectedMemory(PVOID address, PVOID buffer, SIZE_T size);

	DWORD64 SearchPattern(void* baseAddress, DWORD64 size, const char* pattern);
	DWORD64 SearchPatternInImage(void* base, const char* pattern);

	void ModifyIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine);

	UINT32 SwapEndian32(UINT32 value);
	USHORT SwapEndian16(USHORT value);

	NTSTATUS CreateSpoofedKey(TPM2B_PUBLIC_KEY_RSA* inputKey);

	void RandomizeString(char* string);
	ULONG RandomNumber(ULONG min, ULONG max);

	PVOID FindCodeCave(PVOID moduleBase, SIZE_T size);
	bool BuildTrampoline(PVOID codeCave, PVOID destination);
}