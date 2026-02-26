#include "includes.hpp"

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))

PVOID Mem::Allocate(SIZE_T size)
{
	return ExAllocatePoolWithTag(NonPagedPool, size, 0x656B6F54);
}

void Mem::Free(PVOID memory)
{
	if (memory)
	{
		ExFreePoolWithTag(memory, 0x656B6F54);
	}
}

char* Mem::StringCompare(const char* haystack, const char* needle)
{
	do
	{
		const char* h = haystack;
		const char* n = needle;
		while (tolower(static_cast<unsigned char>(*h)) == tolower(static_cast<unsigned char>(*n)) && *n)
		{
			h++;
			n++;
		}

		if (*n == 0)
			return const_cast<char*>(haystack);
	} while (*haystack++);
	return nullptr;
}

PVOID Mem::GetKernelModule(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

	PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(Mem::Allocate(size));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
		goto end;

	for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
	{
		ULONG64 pointer = reinterpret_cast<ULONG64>(&moduleList->Modules[i]);
		pointer += sizeof(SYSTEM_MODULE);
		if (pointer > (reinterpret_cast<ULONG64>(moduleList) + size))
			break;

		SYSTEM_MODULE module = moduleList->Modules[i];
		module.ImageName[255] = '\0';
		if (StringCompare(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}

end:
	Mem::Free(moduleList);
	return address;
}

bool Mem::WriteProtectedMemory(PVOID address, PVOID buffer, SIZE_T size)
{
	PMDL mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, nullptr);
	if (!mdl)
		return false;

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	PVOID mapping = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
	if (!mapping)
	{
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return false;
	}

	NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		MmUnmapLockedPages(mapping, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return false;
	}

	memcpy(mapping, buffer, size);

	MmUnmapLockedPages(mapping, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	return true;
}

ULONG64 Mem::SearchPattern(void* baseAddress, ULONG64 size, const char* pattern)
{
	BYTE* firstMatch = nullptr;
	const char* currentPattern = pattern;

	BYTE* start = static_cast<BYTE*>(baseAddress);
	BYTE* end = start + size;

	for (BYTE* current = start; current < end; current++)
	{
		BYTE byte = currentPattern[0]; if (!byte) return reinterpret_cast<ULONG64>(firstMatch);
		if (byte == '\?' || *static_cast<BYTE*>(current) == GET_BYTE(byte, currentPattern[1]))
		{
			if (!firstMatch) firstMatch = current;
			if (!currentPattern[2]) return reinterpret_cast<ULONG64>(firstMatch);
			((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
		}
		else
		{
			currentPattern = pattern;
			firstMatch = nullptr;
		}
	}

	return 0;
}

ULONG64 Mem::SearchPatternInImage(void* base, const char* pattern)
{
	ULONG64 match = 0;

	PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, ".text", 5) == 0 || *reinterpret_cast<DWORD32*>(section->Name) == 'EGAP')
		{
			match = SearchPattern(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
			if (match)
				break;
		}
	}

	return match;
}

void Mem::ModifyIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine)
{
	PIOC_REQUEST request = static_cast<PIOC_REQUEST>(Mem::Allocate(sizeof(IOC_REQUEST)));
	if (!request) return;

	request->Buffer = irp->AssociatedIrp.SystemBuffer;
	request->Size = ioc->Parameters.DeviceIoControl.OutputBufferLength;
	request->OriginalContext = ioc->Context;
	request->Original = ioc->CompletionRoutine;

	ioc->Control = SL_INVOKE_ON_SUCCESS;
	ioc->Context = request;
	ioc->CompletionRoutine = routine;
}

UINT32 Mem::SwapEndian32(UINT32 value)
{
	return ((value >> 24) & 0x000000FF) |
		((value >> 8) & 0x0000FF00) |
		((value << 8) & 0x00FF0000) |
		((value << 24) & 0xFF000000);
}

USHORT Mem::SwapEndian16(USHORT value)
{
	return ((value >> 8) & 0x00FF) |
		((value << 8) & 0xFF00);
}

NTSTATUS Mem::CreateSpoofedKey(TPM2B_PUBLIC_KEY_RSA* inputKey)
{
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;
	PUCHAR keyBlob = nullptr;

	NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = BCryptGenerateKeyPair(algorithm, &keyHandle, 2048, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	status = BCryptFinalizeKeyPair(keyHandle, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	DWORD keyBlobLength = 0;
	status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &keyBlobLength, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	keyBlob = static_cast<PUCHAR>(Mem::Allocate(keyBlobLength));
	if (!keyBlob)
	{
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB, keyBlob, keyBlobLength, &keyBlobLength, 0);
	if (!NT_SUCCESS(status))
		goto Cleanup;

	memcpy(inputKey->buffer, keyBlob, keyBlobLength);
	inputKey->size = static_cast<UINT16>(keyBlobLength);

Cleanup:
	if (keyBlob)
		Mem::Free(keyBlob);

	if (keyHandle)
		BCryptDestroyKey(keyHandle);

	if (algorithm)
		BCryptCloseAlgorithmProvider(algorithm, 0);

	return status;
}

ULONG Mem::RandomNumber(ULONG min, ULONG max)
{
	ULONG seed = static_cast<ULONG>(__rdtsc());
	return min + (RtlRandomEx(&seed) % (max - min + 1));
}

void Mem::RandomizeString(char* string)
{
	SIZE_T length = strlen(string);
	for (SIZE_T i = 0; i < length; i++)
	{
		if (string[i] >= 'A' && string[i] <= 'Z')
			string[i] = static_cast<char>(Mem::RandomNumber('A', 'Z'));
		else if (string[i] >= 'a' && string[i] <= 'z')
			string[i] = static_cast<char>(Mem::RandomNumber('a', 'z'));
		else if (string[i] >= '0' && string[i] <= '9')
			string[i] = static_cast<char>(Mem::RandomNumber('0', '9'));
	}
}

PVOID Mem::FindCodeCave(PVOID moduleBase, SIZE_T size)
{
	PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
	PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(moduleBase) + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

	for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
	{
		if (memcmp(section->Name, ".text", 5) == 0 || memcmp(section->Name, "PAGE", 4) == 0)
		{
			BYTE* start = reinterpret_cast<BYTE*>(reinterpret_cast<ULONG64>(moduleBase) + section->VirtualAddress);
			BYTE* end = start + section->Misc.VirtualSize;
			SIZE_T matchCount = 0;

			for (BYTE* current = start; current < end; current++)
			{
				if (*current == 0xCC || *current == 0x00 || *current == 0x90)
				{
					matchCount++;
					if (matchCount == size)
					{
						return current - size + 1;
					}
				}
				else
				{
					matchCount = 0;
				}
			}
		}
	}
	return nullptr;
}

bool Mem::BuildTrampoline(PVOID codeCave, PVOID destination)
{
	BYTE shellcode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
	*reinterpret_cast<PVOID*>(&shellcode[2]) = destination;
	return WriteProtectedMemory(codeCave, shellcode, sizeof(shellcode));
}