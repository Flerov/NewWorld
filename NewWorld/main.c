#include <ntifs.h> // new
#include <intrin.h>
#include "main.h"
#include "FuncDefs.h"

// =================================================================
// GLOBAL DATA
// =================================================================
#define MAPPING_NAME L"\\BaseNamedObjects\\MySharedMemory"

PVOID SymbolList;
SIZE_T SymsViewSize;

PRESET_UNICODE_STRING(usDeviceName, CSTRING(DRV_DEVICE));
PRESET_UNICODE_STRING(usSymbolicLinkName, CSTRING(DRV_LINK));

PDEVICE_OBJECT  gpDeviceObject = NULL;
PDEVICE_CONTEXT gpDeviceContext = NULL;

BOOL            gfSpyHookState = FALSE;
BOOL            gfSpyHookPause = FALSE;
BOOL            gfSpyHookFilter = FALSE;
HANDLE          ghSpyHookThread = 0;

BYTE            abHex[] = "0123456789ABCDEF";


// =================================================================
// SYSTEM SERVICE HOOK ENTRIES
// =================================================================

SPY_HOOK_ENTRY aSpyHooks[SDT_SYMBOLS_MAX];

// -----------------------------------------------------------------

NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath);
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverInitialize)
#pragma alloc_text(INIT, DriverEntry)
#endif

typedef struct _SYMBOL {
	CHAR name[32];
	unsigned long long offset;
	LIST_ENTRY ListEntry;
} SYMBOL, * PSYMBOL;


NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath) {
	DWORD i;
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS ns = STATUS_DEVICE_CONFIGURATION_ERROR;

	if ((ns = IoCreateDevice(
							pDriverObject, DEVICE_CONTEXT_,
							&usDeviceName, FILE_DEVICE_SPY,
							0, FALSE, &pDeviceObject))
		== STATUS_SUCCESS) {
		gpDeviceObject = pDeviceObject;
		gpDeviceContext = pDeviceObject->DeviceExtension;

		gpDeviceContext->pDriverObject = pDriverObject;
		gpDeviceContext->pDeviceObject = pDeviceObject;

		MUTEX_INITIALIZE(gpDeviceContext->kmDispatch);
		MUTEX_INITIALIZE(gpDeviceContext->kmProtocol);

		gpDeviceContext->dMisses = 0;

		for (i = 0; i < SPY_CALLS; i++) {
			gpDeviceContext->SpyCalls[i].fInUse = FALSE;
			gpDeviceContext->SpyCalls[i].hThread = 0;
		}
		//SpyWriteReset(&gpDeviceContext->SpyCalls);
	} else {
		//IoDeleteDevice(pDeviceObject); // Can't Delete Device, If IoCreate failed...
	}
	DbgPrint("DriverInitialize - Status: 0x%llx\n", ns);
	return ns;
}

UINT64 GetSymOffset(const char* str) {
	if (SymbolList == NULL)
		return NULL;

	size_t maxSymCount = SymsViewSize / sizeof(SYMBOL);
	PSYMBOL syms = (PVOID)SymbolList;

	for (size_t i = 0; i <= maxSymCount; i++) {
		if (strcmp(syms[i].name, str) == 0) {
			return syms[i].offset;
		}
	}
}

PEPROCESS GetProcess(UINT32 pid, unsigned long long eprocUniqueProcessId, unsigned long long eprocActiveProcessLinks) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + eprocUniqueProcessId);
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	do {
		if (*(UINT32*)CurrentPID == pid) {
			PEPROCESS targetProcess = (PEPROCESS)CurrEProc;

			return targetProcess;
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + eprocUniqueProcessId);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
}

PVOID GetDirectoryTableBase(UINT32 pid, unsigned long long eprocUniqueProcessId, unsigned long long eprocActiveProcessLinks, unsigned long long kprocDirectoryTableBase) {
	// TODO: THIS IS SHIT CHANGE THIS!!!!!
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + eprocUniqueProcessId);
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	do {
		if (*(UINT32*)CurrentPID == pid) {
			PVOID* test = (unsigned long long)CurrEProc + kprocDirectoryTableBase;
			
			return *test;
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + eprocUniqueProcessId);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
}

VOID VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log) {
	//PEPROCESS TargetProcess;
	KAPC_STATE ApcState;
	NTSTATUS status;
	SIZE_T numRec = 0;
	MM_COPY_ADDRESS PhysPML4 = { 0 }; // Physical Page Map Level 4
	MM_COPY_ADDRESS PhysPDPT = { 0 }; // Physical Page Directory Pointer Table
	MM_COPY_ADDRESS PhysPD = { 0 };   // Physical Page Directory
	MM_COPY_ADDRESS PhysPage = { 0 }; // Physical Page Table
	MM_COPY_ADDRESS Phys = { 0 };     // Physical
	//unsigned long long cr3;

	unsigned long long PML4Offset = (addr & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	unsigned long long PDPTOffset = (addr & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	unsigned long long PDOffset = (addr & 0x3FE00000) >> 0x15;       // Page Directory Offset
	unsigned long long PTOffset = (addr & 0x1FF000) >> 0x0C;         // Page Table Offset
	unsigned long long MaskOffset = (addr & 0x1FFFFF);               // Physical Offset

	unsigned long long pml4e = 0x0; // Page Map Level 4 Entry (Pointer)
	unsigned long long pdpte = 0x0; // Page Directory Pointer Table Entry (Pointer)
	unsigned long long pde = 0x0;   // Page Directory Entry (Pointer)
	unsigned long long pte = 0x0;   // Page Table Entry (Pointer)
	unsigned long long physAdr = 0x0; // unused
	unsigned long long IA32_PAT_MSR = __readmsr(0x277); // Read PAT (Page Attribute Table)

	PML4E* PML4ERaw = 0x0; // Page Map Level 4 Entry
	PDPTE* PDPTERaw = 0x0; // Page Directory Pointer Table Entry
	PDE* PDERaw		= 0x0; // Page Directory Entry
	PTE* PTERaw		= 0x0; // Page Table Entry
	PHYSICAL_1GB* PHYSRaw1GB = 0x0; // Huge Page
	PHYSICAL_2MB* PHYSRaw2MB = 0x0; // Large Page
	PHYSICAL_4KB* PHYSRaw4KB = 0x0; // Page

	//TargetProcess = GetProcess(pid);
	KeStackAttachProcess(TargetProcess, &ApcState);
	//cr3 = GetDirectoryTableBase(pid);

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = cr3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e) / 2, MM_COPY_MEMORY_PHYSICAL, &numRec);
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte) / 2, MM_COPY_MEMORY_PHYSICAL, &numRec);
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde) / 2, MM_COPY_MEMORY_PHYSICAL, &numRec);
		PDERaw = (PDE*)&pde;
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte) / 2, MM_COPY_MEMORY_PHYSICAL, &numRec);
			PTERaw = (PTE*)&pte;
			Phys.PhysicalAddress.QuadPart = (pte & 0xFFFFF000) + MaskOffset;
			PHYSRaw4KB = (PHYSICAL_4KB*)&Phys.PhysicalAddress.QuadPart; // TODO for 4KB and 1GB
		}
		else {
			Phys.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + MaskOffset;
			PHYSRaw2MB = (PHYSICAL_2MB*)&Phys.PhysicalAddress.QuadPart;
		}
	}
	else {
		Phys.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + MaskOffset;
		PHYSRaw1GB = (PHYSICAL_1GB*)&Phys.PhysicalAddress.QuadPart;
	}
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(TargetProcess);

	if (log) {
		DbgPrint("[+] cr3: 0x%llx\n", cr3);
		DbgPrint("[+] PML4E Raw -\n"
			"\t[*] Accessed: %llx\n"
			"\t[*] ExecuteDisable: %llx\n"
			"\t[*] PageCacheDisable: %llx\n"
			"\t[*] PageFrameNumber: %llx\n"
			"\t[*] PageSize: %llx\n"
			"\t[*] PageWriteThrough: %llx\n"
			"\t[*] Present: %llx\n"
			"\t[*] ProtectionKey: %llx\n"
			"\t[*] ReadWrite: %llx\n"
			"\t[*] UseSupervisor: %llx\n"
			"\t[*] Value: %llx\n",
			PML4ERaw->Accessed, PML4ERaw->ExecuteDisable, PML4ERaw->PageCacheDisable,
			PML4ERaw->PageFrameNumber, PML4ERaw->PageSize, PML4ERaw->PageWriteThrough,
			PML4ERaw->Present, PML4ERaw->ProtectionKey, PML4ERaw->ReadWrite, PML4ERaw->UserSupervisor, PML4ERaw->Value);
		DbgPrint("[+] PDPTE Raw -\n"
			"\t[*] Accessed: %llx\n"
			"\t[*] ExecuteDisable: %llx\n"
			"\t[*] PageCacheDisable: %llx\n"
			"\t[*] PageFrameNumber1GB: %llx\n"
			"\t[*] PageFrameNumber4KB: %llx\n"
			"\t[*] PageSize: %llx\n"
			"\t[*] PageWriteThrough: %llx\n"
			"\t[*] PAT: %llx\n"
			"\t[*] Present: %llx\n"
			"\t[*] ProtectionKey: %llx\n"
			"\t[*] ReadWrite: %llx\n"
			"\t[*] UserSupervisor: %llx\n"
			"\t[*] Value: %llx\n",
			PDPTERaw->Accessed, PDPTERaw->ExecuteDisable, PDPTERaw->PageCacheDisable,
			PDPTERaw->PageFrameNumber1GB, PDPTERaw->PageFrameNumber4KB, PDPTERaw->PageSize, PDPTERaw->PageWriteThrough,
			PDPTERaw->PAT, PDPTERaw->Present, PDPTERaw->ProtectionKey, PDPTERaw->ReadWrite,
			PDPTERaw->UserSupervisor, PDPTERaw->Value);
		DbgPrint("[*] PDPTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
			PDPTERaw->PAT, PDPTERaw->PageCacheDisable, PDPTERaw->PageWriteThrough,
			PDPTERaw->PAT + PDPTERaw->PageCacheDisable + PDPTERaw->PageWriteThrough, IA32_PAT_MSR);
		if (PDERaw != 0x0) {
			DbgPrint("[+] PDE Raw-\n"
				"\t[*] Accessed: %llx\n"
				"\t[*] Available1: %llx\n"
				"\t[*] Available2: %llx\n"
				"\t[*] Available3: %llx\n"
				"\t[*] Dirty: %llx\n"
				"\t[*] ExecuteDisable: %llx\n"
				"\t[*] Global: %llx\n"
				"\t[*] PageCacheDisable: %llx\n"
				"\t[*] PageFrameNumber: %llx\n"
				"\t[*] PageFrameNumber4KB: %llx\n"
				"\t[*] PageSize: %llx\n"
				"\t[*] PageWriteThrough: %llx\n"
				"\t[*] PAT: %llx\n"
				"\t[*] Present: %llx\n"
				"\t[*] ReadWrite: %llx\n"
				"\t[*] UserSupervisor: %llx\n"
				"\t[*] Value: %llx\n",
				PDERaw->Accessed, PDERaw->Available1, PDERaw->Available2, PDERaw->Available3, PDERaw->Dirty, PDERaw->ExecuteDisable, PDERaw->Global, PDERaw->PageCacheDisable,
				PDERaw->PageFrameNumber, PDERaw->PageFrameNumber4KB,  PDERaw->PageSize, PDERaw->PageWriteThrough, PDERaw->PAT,
				PDERaw->Present, PDERaw->ReadWrite, PDERaw->UserSupervisor, PDERaw->Value);
			DbgPrint("[*] PDE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
				PDERaw->PAT, PDERaw->PageCacheDisable, PDERaw->PageWriteThrough,
				PDERaw->PAT + PDERaw->PageCacheDisable + PDERaw->PageWriteThrough, IA32_PAT_MSR);
			if (PTERaw != 0x0) {
				DbgPrint("[+] PTE Raw-\n"
					"\t[*] Accessed: %llx\n"
					"\t[*] Dirty: %llx\n"
					"\t[*] ExecuteDisable: %llx\n"
					"\t[*] Global: %llx\n"
					"\t[*] PageAccessType: %llx\n"
					"\t[*] PageCacheDisable: %llx\n"
					"\t[*] PageFrameNumber: %llx\n"
					"\t[*] PageWriteThrough: %llx\n"
					"\t[*] Present: %llx\n"
					"\t[*] ProtectionKey: %llx\n"
					"\t[*] ReadWrite: %llx\n"
					"\t[*] UserSupervisor: %llx\n"
					"\t[*] Value: %llx\n",
					PTERaw->Accessed, PTERaw->Dirty, PTERaw->ExecuteDisable, PTERaw->Global, PTERaw->PageAccessType, PTERaw->PageCacheDisable, PTERaw->PageFrameNumber, PTERaw->PageWriteThrough, PTERaw->Present,
					PTERaw->ProtectionKey, PTERaw->ReadWrite, PTERaw->UserSupervisor, PTERaw->Value);
				DbgPrint("[*] PTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
					PTERaw->PageAccessType, PTERaw->PageCacheDisable, PTERaw->PageWriteThrough,
					PTERaw->PageAccessType + PTERaw->PageCacheDisable + PTERaw->PageWriteThrough, IA32_PAT_MSR);
				DbgPrint("[+] PHYS 1GB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw4KB->Offset, PHYSRaw4KB->PageNumber, PHYSRaw4KB->Value);
			} else {
				DbgPrint("[+] PHYS 2MB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw2MB->Offset, PHYSRaw2MB->PageNumber, PHYSRaw2MB->Value);
			}
		} else {
			DbgPrint("[+] PHYS 1GB-\n"
				"\t[*] Offset: %llx\n"
				"\t[*] PageNumber: %llx\n"
				"\t[*] Value: %llx\n",
				PHYSRaw1GB->Offset, PHYSRaw1GB->PageNumber, PHYSRaw1GB->Value);
		}
	}

	// Test Write
	//PDERaw->Available1 = 0;
	////PDERaw->Present = 0;
	//
	//PVOID tmp = MmGetVirtualForPhysical(PhysPD.PhysicalAddress);
	//DbgPrint("VirtualForPhysical: 0x%llx\n", tmp);
	//
	//KIRQL irql = KeGetCurrentIrql();
	//if (irql >= DISPATCH_LEVEL) {
	//	DbgPrint("[-] Current IRQL is at or above DISPATCH_LEVEL: %u\n", irql);
	//	DbgPrint("[-] Skip write\n");
	//}
	//else {
	//	DbgPrint("[+] Current IRQL is below DISPATCH_LEVEL: %u\n", irql);
	//	PVOID ret = memcpy(tmp, &PDERaw->Value, sizeof(PDERaw->Value));
	//	if (!ret)
	//		DbgPrint("[-] memcpy failed\n");
	//	DbgPrint("[+] Written\n");
	//}
	//
	//status = MmCopyMemory(&pde, PhysPD, sizeof(pde) / 2, MM_COPY_MEMORY_PHYSICAL, &numRec);
	//PDE* test = (PDE*)&pde;
	//DbgPrint("[+] PDE Raw-\n"
	//	"\t[*] Accessed: %llx\n"
	//	"\t[*] Available1: %llx\n"
	//	"\t[*] Available2: %llx\n"
	//	"\t[*] Available3: %llx\n"
	//	"\t[*] Dirty: %llx\n"
	//	"\t[*] ExecuteDisable: %llx\n"
	//	"\t[*] Global: %llx\n"
	//	"\t[*] PageCacheDisable: %llx\n"
	//	"\t[*] PageFrameNumber: %llx\n"
	//	"\t[*] PageFrameNumber4KB: %llx\n"
	//	"\t[*] PageSize: %llx\n"
	//	"\t[*] PageWriteThrough: %llx\n"
	//	"\t[*] PAT: %llx\n"
	//	"\t[*] Present: %llx\n"
	//	"\t[*] ReadWrite: %llx\n"
	//	"\t[*] UserSupervisor: %llx\n"
	//	"\t[*] Value: %llx\n",
	//	test->Accessed, test->Available1, test->Available2, test->Available3, test->Dirty, test->ExecuteDisable, test->Global, test->PageCacheDisable,
	//	test->PageFrameNumber, test->PageFrameNumber4KB, test->PageSize, test->PageWriteThrough, test->PAT,
	//	test->Present, test->ReadWrite, test->UserSupervisor, test->Value);
	//DbgPrint("[*] PDE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
	//	test->PAT, test->PageCacheDisable, test->PageWriteThrough,
	//	test->PAT + test->PageCacheDisable + test->PageWriteThrough, IA32_PAT_MSR);
	return;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath) {
	PDRIVER_DISPATCH* ppdd;
	//NTSTATUS ns = STATUS_DEVICE_CONFIGURATION_ERROR;
	NTSTATUS ns = STATUS_SUCCESS; // TODO

	if ((ns = DriverInitialize(pDriverObject, pusRegistryPath)) == STATUS_SUCCESS) {
		ppdd = pDriverObject->MajorFunction;

		//ppdd[IRP_MJ_CREATE] =
		//	ppdd[IRP_MJ_CREATE_NAMED_PIPE] =
		//	ppdd[IRP_MJ_CLOSE] =
		//	ppdd[IRP_MJ_READ] =
		//	ppdd[IRP_MJ_WRITE] =
		//	ppdd[IRP_MJ_QUERY_INFORMATION] =
		//	ppdd[IRP_MJ_SET_INFORMATION] =
		//	ppdd[IRP_MJ_QUERY_EA] =
		//	ppdd[IRP_MJ_SET_EA] =
		//	ppdd[IRP_MJ_FLUSH_BUFFERS] =
		//	ppdd[IRP_MJ_QUERY_VOLUME_INFORMATION] =
		//	ppdd[IRP_MJ_SET_VOLUME_INFORMATION] =
		//	ppdd[IRP_MJ_DIRECTORY_CONTROL] =
		//	ppdd[IRP_MJ_FILE_SYSTEM_CONTROL] =
		//	ppdd[IRP_MJ_DEVICE_CONTROL] =
		//	ppdd[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
		//	ppdd[IRP_MJ_SHUTDOWN] =
		//	ppdd[IRP_MJ_LOCK_CONTROL] =
		//	ppdd[IRP_MJ_CLEANUP] =
		//	ppdd[IRP_MJ_CREATE_MAILSLOT] =
		//	ppdd[IRP_MJ_QUERY_SECURITY] =
		//	ppdd[IRP_MJ_SET_SECURITY] =
		//	ppdd[IRP_MJ_POWER] =
		//	ppdd[IRP_MJ_SYSTEM_CONTROL] =
		//	ppdd[IRP_MJ_DEVICE_CHANGE] =
		//	ppdd[IRP_MJ_QUERY_QUOTA] =
		//	ppdd[IRP_MJ_SET_QUOTA] =
		//	ppdd[IRP_MJ_PNP] = DriverDispatcher;
		pDriverObject->DriverUnload = DriverUnload;

	// ================================================
	// READ SECTION FROM USER-MODE (SYMBOL-INFORMATION)
	// ================================================
		HANDLE hSection;
		OBJECT_ATTRIBUTES attr;
		UNICODE_STRING sectionName;
		PVOID sectionObject = NULL;

		RtlInitUnicodeString(&sectionName, MAPPING_NAME);
		InitializeObjectAttributes(&attr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		NTSTATUS status = ZwOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE, &attr);
		if (!NT_SUCCESS(status) || hSection == NULL) {
			DbgPrint("[-] ZwOpenSection failed - Status: %d\n", status);
			return status;
		}

		SymsViewSize = 0; // 0 means "use full section size"
		LARGE_INTEGER SectionOffset = { 0 }; // Map from start

		PVOID vSection = 0;
		status = ZwMapViewOfSection(hSection, ZwCurrentProcess(), &vSection, 
			0, 0, NULL, &SymsViewSize, ViewUnmap,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] ZwMapViewOfSection failed - status: %d\n", status);
			return status;
		}

		// Make sure the Section is not paged-out
		MDL* pMdl = IoAllocateMdl(vSection, SymsViewSize, FALSE, FALSE, NULL);
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);

		// Allocate enough space to copy section' content
		SymbolList = ExAllocatePool(NonPagedPool, SymsViewSize);
		if (!(SymbolList == NULL)) {
			memcpy(SymbolList, vSection, SymsViewSize);
			DbgPrint("[*] Section size: %zu Bytes | Section Base: 0x%llx | SymbolList Base: 0x%llx\n",
				SymsViewSize, vSection, SymbolList);
		} else {
			DbgPrint("[-] Could not copy section to pool\n");
			DbgPrint("\tSection Base: 0x%llx\n", hSection);
			DbgBreakPoint();
		}

		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);
		ZwUnmapViewOfSection(ZwCurrentProcess(), hSection);
		ZwClose(hSection);

		// TODO: Use RTL_HASHTABLE instead
		unsigned long long eprocUniqueProcessId = GetSymOffset("eprocUniqueProcessId");
		unsigned long long eprocActiveProcessLinks = GetSymOffset("eprocActiveProcessLinks");
		unsigned long long kprocDirectoryTableBase = GetSymOffset("kprocDirectoryTableBase");
		unsigned long long KeServiceDescriptorTableOffset = GetSymOffset("KeServiceDescriptorTable");
		unsigned long long ntBase = GetSymOffset("ntBase");
		unsigned long long KeServiceDescriptorTable = ntBase + KeServiceDescriptorTableOffset;
		DbgPrint("[+] eprocUniqueProcessId at: 0x%llx\n", eprocUniqueProcessId);
		DbgPrint("[+] eprocActiveProcessLinks at: 0x%llx\n", eprocActiveProcessLinks);
		DbgPrint("[+] kprocDirectoryTableBase at: 0x%llx\n", kprocDirectoryTableBase);
		DbgPrint("[+] KeServiceDescriptorTable at: 0x%llx\n", KeServiceDescriptorTable);
		DbgPrint("[+] KeServiceDescriptorTableOffset at: 0x%llx\n", KeServiceDescriptorTableOffset);
		DbgPrint("[+] ntBase at: 0x%llx\n", ntBase);
		PHYSICAL_ADDRESS phys =  MmGetPhysicalAddress(KeServiceDescriptorTable);
		DbgPrint("[+] Physical: QuadPart: 0x%llx | HighPart: 0x%llx | LowPart: 0x%llx | u_HighPart: 0x%llx | u_LowPart: 0x%llx\n",
			phys.QuadPart, phys.HighPart, phys.LowPart, phys.u.HighPart, phys.u.LowPart);

		unsigned long long cr3 = GetDirectoryTableBase(4, eprocUniqueProcessId, eprocActiveProcessLinks, kprocDirectoryTableBase);
		PEPROCESS TargetProcess = GetProcess(4, eprocUniqueProcessId, eprocActiveProcessLinks);
		DbgPrint("[+] Target: %d | cr3 at: 0x%llx\n", 4, cr3);
		VirtToPhys(KeServiceDescriptorTable, TargetProcess, cr3, TRUE);

	//TODO: SpyDispatcher();
	//TODO: SpyHookInitialize();
	}
	return ns;
}

// =================================================================
// DRIVER REQUEST HANDLER
// =================================================================

//NTSTATUS DriverDispatcher(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
//	return(pDeviceObject == gpDeviceObject
//		? DeviceDispatcher(gpDeviceContext, pIrp)
//		: STATUS_INVALID_PARAMETER);
//}

// -----------------------------------------------------------------

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	//SpyHookCleanup();

	if (SymbolList != NULL)
		ExFreePool(SymbolList);

	IoDeleteSymbolicLink(&usSymbolicLinkName);
	IoDeleteDevice(gpDeviceObject);
	return;
}