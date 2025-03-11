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
		SpyWriteReset(&gpDeviceContext->SpyCalls);
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

PEPROCESS GetProcess(UINT32 pid) {
	// TODO: THIS IS SHIT CHANGE THIS!!!!!
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + 0x440);
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + 0x448);
	do {
		if (*(UINT32*)CurrentPID == pid) {
			PEPROCESS targetProcess = (PEPROCESS)CurrEProc;

			return targetProcess;
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - 0x448;
		CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + 0x440);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + 0x448);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
}

PVOID GetDirectoryTableBase(UINT32 pid) {
	// TODO: THIS IS SHIT CHANGE THIS!!!!!
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + 0x440);
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + 0x448);
	do {
		if (*(UINT32*)CurrentPID == pid) {
			PVOID* test = (unsigned long long)CurrEProc + 0x28;
			
			return *test;
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - 0x448;
		CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + 0x440);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + 0x448);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
}

VOID VirtToPhys(unsigned long long addr, UINT32 pid, BOOLEAN log) {
	KAPC_STATE ApcState;
	PEPROCESS TargetProcess;
	NTSTATUS status;
	SIZE_T numRec = 0;
	MM_COPY_ADDRESS PhysPML4 = { 0 };
	MM_COPY_ADDRESS PhysPDPT = { 0 };
	MM_COPY_ADDRESS PhysPD = { 0 };
	MM_COPY_ADDRESS PhysPage = { 0 };
	MM_COPY_ADDRESS Phys = { 0 };
	unsigned long long cr3;

	// TODO: !Note: This currently only works for LARGE_PAGE
	unsigned long long PML4Offset = (addr & 0xFF8000000000) >> 0x27;
	unsigned long long PDPTOffset = (addr & 0x7FC0000000) >> 0x1E;
	unsigned long long PDOffset = (addr & 0x3FE00000) >> 0x15;
	unsigned long long PTOffset = (addr & 0x1FF000) >> 0x0C;
	unsigned long long MaskOffset = (addr & 0x1FFFFF);

	unsigned long long pml4e = 0x0;
	unsigned long long pdpte = 0x0;
	unsigned long long pde = 0x0;
	unsigned long long pte = 0x0;
	unsigned long long physAdr = 0x0; // unused
	unsigned long long IA32_PAT_MSR = __readmsr(0x277); // Read PAT (Page Attribute Table)

	PML4E* PML4ERaw = 0x0;
	PDPTE* PDPTERaw = 0x0;
	PDE* PDERaw		= 0x0;
	PTE* PTERaw		= 0x0;
	PHYSICAL_1GB* PHYSRaw1GB = 0x0;
	PHYSICAL_2MB* PHYSRaw2MB = 0x0;
	PHYSICAL_4KB* PHYSRaw4KB = 0x0;

	// https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html
	// https://www.unknowncheats.me/forum/anti-cheat-bypass/668915-mmmapiospace-vulnerable-drivers.html
	// TODO: Clean-Up - Error-Handling - Put in own function
	TargetProcess = GetProcess(pid);
	KeStackAttachProcess(TargetProcess, &ApcState);
	cr3 = GetDirectoryTableBase(pid);

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

	if (!NT_SUCCESS(status))
		DbgPrint("Something Failed\n");
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(TargetProcess);

	if (log) {
		DbgPrint("[+] cr3: 0x%llx\n", cr3);
		DbgPrint("[+] PhysPML4.PhysicalAddress.QuadPart: 0x%llx\n", PhysPML4.PhysicalAddress.QuadPart);
		DbgPrint("[+] Phys-Read -> PML4E: 0x%llx\n", pml4e);
		DbgPrint("[+] PhysPDPT.PhysicalAddress.QuadPart: 0x%llx\n", PhysPDPT.PhysicalAddress.QuadPart);
		DbgPrint("[+] Phys-Read -> PDPTE: 0x%llx\n", pdpte);
		DbgPrint("[+] PhysPD.PhysicalAddress.QuadPart: 0x%llx\n", PhysPD.PhysicalAddress.QuadPart);
		DbgPrint("[+] Phys-Read -> PDE: 0x%llx\n", pde);
		DbgPrint("[+] Phys-Read -> Large page mapped phys: 0x%llx\n", PhysPage.PhysicalAddress.QuadPart);
		DbgPrint("[+] Virtual address 0x%llx translates to physical address 0x%llx\n", KeServiceDescriptorTable, PhysPage.PhysicalAddress.QuadPart);
		DbgPrint("PML4E Raw -\n"
			"\tAccessed: %llx\n"
			"\tExecuteDisable: %llx\n"
			"\tPageCacheDisable: %llx\n"
			"\tPageFrameNumber: %llx\n"
			"\tPageSize: %llx\n"
			"\tPageWriteThrough: %llx\n"
			"\tPresent: %llx\n"
			"\tProtectionKey: %llx\n"
			"\tReadWrite: %llx\n"
			"\tUseSupervisor: %llx\n"
			"\tValue: %llx\n",
			PML4ERaw->Accessed, PML4ERaw->ExecuteDisable, PML4ERaw->PageCacheDisable,
			PML4ERaw->PageFrameNumber, PML4ERaw->PageSize, PML4ERaw->PageWriteThrough,
			PML4ERaw->Present, PML4ERaw->ProtectionKey, PML4ERaw->ReadWrite, PML4ERaw->UserSupervisor, PML4ERaw->Value);
		DbgPrint("[+] PDPTE Raw -\n"
			"\tAccessed: %llx\n"
			"\tExecuteDisable: %llx\n"
			"\tPageCacheDisable: %llx\n"
			"\tPageFrameNumber1GB: %llx\n"
			"\tPageFrameNumber4KB: %llx\n"
			"\tPageSize: %llx\n"
			"\tPageWriteThrough: %llx\n"
			"\tPAT: %llx\n"
			"\tPresent: %llx\n"
			"\tProtectionKey: %llx\n"
			"\tReadWrite: %llx\n"
			"\tUserSupervisor: %llx\n"
			"\tValue: %llx\n",
			PDPTERaw->Accessed, PDPTERaw->ExecuteDisable, PDPTERaw->PageCacheDisable,
			PDPTERaw->PageFrameNumber1GB, PDPTERaw->PageFrameNumber4KB, PDPTERaw->PageSize, PDPTERaw->PageWriteThrough,
			PDPTERaw->PAT, PDPTERaw->Present, PDPTERaw->ProtectionKey, PDPTERaw->ReadWrite,
			PDPTERaw->UserSupervisor, PDPTERaw->Value);
		DbgPrint("[+] PDPTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
			PDPTERaw->PAT, PDPTERaw->PageCacheDisable, PDPTERaw->PageWriteThrough,
			PDPTERaw->PAT + PDPTERaw->PageCacheDisable + PDPTERaw->PageWriteThrough, IA32_PAT_MSR);
		if (PDERaw != 0x0) {
			DbgPrint("[+] PDE Raw-\n"
				"\tAccessed: %llx\n"
				"\tAvailable: %llx\n"
				"\tDirty: %llx\n"
				"\tExecuteDisable: %llx\n"
				"\tGlobal: %llx\n"
				"\tPageCacheDisable: %llx\n"
				"\tPageFrameNumber: %llx\n"
				"\tPageFrameNumber4KB: %llx\n"
				"\tPageSize: %llx\n"
				"\tPageWriteThrough: %llx\n"
				"\tPAT: %llx\n"
				"\tPresent: %llx\n"
				"\tReadWrite: %llx\n"
				"\tUserSupervisor: %llx\n"
				"\tValue: %llx\n",
				PDERaw->Accessed, PDERaw->Available, PDERaw->Dirty, PDERaw->ExecuteDisable, PDERaw->Global, PDERaw->PageCacheDisable, 
				PDERaw->PageFrameNumber, PDERaw->PageFrameNumber4KB,  PDERaw->PageSize, PDERaw->PageWriteThrough, PDERaw->PAT,
				PDERaw->Present, PDERaw->ReadWrite, PDERaw->UserSupervisor, PDERaw->Value);
			DbgPrint("[+] PDE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
				PDERaw->PAT, PDERaw->PageCacheDisable, PDERaw->PageWriteThrough,
				PDERaw->PAT + PDERaw->PageCacheDisable + PDERaw->PageWriteThrough, IA32_PAT_MSR);
			if (PTERaw != 0x0) {
				DbgPrint("[+] PTE Raw-\n"
					"\tAccessed: %llx\n"
					"\tDirty: %llx\n"
					"\tExecuteDisable: %llx\n"
					"\tGlobal: %llx\n"
					"\tPageAccessType: %llx\n"
					"\tPageCacheDisable: %llx\n"
					"\tPageFrameNumber: %llx\n"
					"\tPageWriteThrough: %llx\n"
					"\tPresent: %llx\n"
					"\tProtectionKey: %llx\n"
					"\tReadWrite: %llx\n"
					"\tUserSupervisor: %llx\n"
					"\tValue: %llx\n",
					PTERaw->Accessed, PTERaw->Dirty, PTERaw->ExecuteDisable, PTERaw->Global, PTERaw->PageAccessType, PTERaw->PageCacheDisable, PTERaw->PageFrameNumber, PTERaw->PageWriteThrough, PTERaw->Present,
					PTERaw->ProtectionKey, PTERaw->ReadWrite, PTERaw->UserSupervisor, PTERaw->Value);
				DbgPrint("[+] PTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
					PTERaw->PageAccessType, PTERaw->PageCacheDisable, PTERaw->PageWriteThrough,
					PTERaw->PageAccessType + PTERaw->PageCacheDisable + PTERaw->PageWriteThrough, IA32_PAT_MSR);
				DbgPrint("[+] PHYS 1GB-\n"
					"\tOffset: %llx\n"
					"\tPageNumber: %llx\n"
					"\tValue: %llx\n",
					PHYSRaw4KB->Offset, PHYSRaw4KB->PageNumber, PHYSRaw4KB->Value);
			} else {
				DbgPrint("[+] PHYS 1GB-\n"
					"\tOffset: %llx\n"
					"\tPageNumber: %llx\n"
					"\tValue: %llx\n",
					PHYSRaw2MB->Offset, PHYSRaw2MB->PageNumber, PHYSRaw2MB->Value);
			}
		} else {
			DbgPrint("[+] PHYS 1GB-\n"
				"\tOffset: %llx\n"
				"\tPageNumber: %llx\n"
				"\tValue: %llx\n",
				PHYSRaw1GB->Offset, PHYSRaw1GB->PageNumber, PHYSRaw1GB->Value);
		}
	}
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath) {
	PDRIVER_DISPATCH* ppdd;
	//NTSTATUS ns = STATUS_DEVICE_CONFIGURATION_ERROR;
	NTSTATUS ns = STATUS_SUCCESS; // TODO

	if ((ns = DriverInitialize(pDriverObject, pusRegistryPath)) == STATUS_SUCCESS) {
		ppdd = pDriverObject->MajorFunction;

		ppdd[IRP_MJ_CREATE] =
			ppdd[IRP_MJ_CREATE_NAMED_PIPE] =
			ppdd[IRP_MJ_CLOSE] =
			ppdd[IRP_MJ_READ] =
			ppdd[IRP_MJ_WRITE] =
			ppdd[IRP_MJ_QUERY_INFORMATION] =
			ppdd[IRP_MJ_SET_INFORMATION] =
			ppdd[IRP_MJ_QUERY_EA] =
			ppdd[IRP_MJ_SET_EA] =
			ppdd[IRP_MJ_FLUSH_BUFFERS] =
			ppdd[IRP_MJ_QUERY_VOLUME_INFORMATION] =
			ppdd[IRP_MJ_SET_VOLUME_INFORMATION] =
			ppdd[IRP_MJ_DIRECTORY_CONTROL] =
			ppdd[IRP_MJ_FILE_SYSTEM_CONTROL] =
			ppdd[IRP_MJ_DEVICE_CONTROL] =
			ppdd[IRP_MJ_INTERNAL_DEVICE_CONTROL] =
			ppdd[IRP_MJ_SHUTDOWN] =
			ppdd[IRP_MJ_LOCK_CONTROL] =
			ppdd[IRP_MJ_CLEANUP] =
			ppdd[IRP_MJ_CREATE_MAILSLOT] =
			ppdd[IRP_MJ_QUERY_SECURITY] =
			ppdd[IRP_MJ_SET_SECURITY] =
			ppdd[IRP_MJ_POWER] =
			ppdd[IRP_MJ_SYSTEM_CONTROL] =
			ppdd[IRP_MJ_DEVICE_CHANGE] =
			ppdd[IRP_MJ_QUERY_QUOTA] =
			ppdd[IRP_MJ_SET_QUOTA] =
			ppdd[IRP_MJ_PNP] = DriverDispatcher;
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
			DbgPrint("[-] Could not copy seciton to pool\n");
			DbgPrint("\tSection Base: 0x%llx\n", hSection);
			DbgBreakPoint();
		}
		//DbgBreakPoint();
		// TEST
		PSPY_PAGE_ENTRY pspe = NULL;
		//
		//if (vSection != NULL) {
		//pspe = SpyMemoryPageEntry(&vSection, pspe);
		//	DbgPrint("Page Entry for Section: 0x%llx\n\tdSize: %d | fPresent: %d | pe: 0x%llx ->\n",
		//		pspe, pspe->dSize, pspe->fPresent, pspe->pe);
		//	DbgPrint("\t\tdValue (packed value): %d\n", pspe->pe.dValue);
		//	DbgPrint("\t\tpdbr (page-directory Base Register): 0x%llx ->\n", pspe->pe.pdbr);
		//	DbgPrint("\t\t\tdValue (packed value):          %d\n", pspe->pe.pdbr.dValue);
		//	DbgPrint("\t\t\tPCD (page-level cache disabled): %d\n", pspe->pe.pdbr.PCD);
		//	DbgPrint("\t\t\tPFN (page-frame number):         %d\n", pspe->pe.pdbr.PFN);
		//	DbgPrint("\t\t\tPFN (page-level write-through):  %d\n", pspe->pe.pdbr.PWT);
		//	DbgPrint("\t\tpde4K (page-directory entry (4-KB page)): 0x%llx ->\n", pspe->pe.pde4K);
		//	DbgPrint("\t\t\tA (accessed):                     %d\n", pspe->pe.pde4K.A);
		//	DbgPrint("\t\t\tAvailable (avail. to devs):       %d\n", pspe->pe.pde4K.Available);
		//	DbgPrint("\t\t\tdValue (packed value):            %d\n", pspe->pe.pde4K.dValue);
		//	DbgPrint("\t\t\tG (global page):                  %d\n", pspe->pe.pde4K.G);
		//	DbgPrint("\t\t\tP (Present (1=present)):          %d\n", pspe->pe.pde4K.P);
		//	DbgPrint("\t\t\tPCD (page-level cache disabled):  %d\n", pspe->pe.pde4K.PCD);
		//	DbgPrint("\t\t\tPFN (page-frame number):          %d\n", pspe->pe.pde4K.PFN);
		//	DbgPrint("\t\t\tPS (page size (0 = 4-KB page)):   %d\n", pspe->pe.pde4K.PS);
		//	DbgPrint("\t\t\tPWT (page-level write-through):   %d\n", pspe->pe.pde4K.PWT);
		//	DbgPrint("\t\t\tRW (read/write):                  %d\n", pspe->pe.pde4K.RW);
		//	DbgPrint("\t\t\tUS (user/supervisor):             %d\n", pspe->pe.pde4K.US);
		//	DbgPrint("\t\tpde4M (page-directory entry (4-MB page)): 0x%llx ->\n", pspe->pe.pde4M);
		//	DbgPrint("\t\t\tA (accessed):                     %d\n", pspe->pe.pde4M.A);
		//	DbgPrint("\t\t\tAvailable (avail. to devs):       %d\n", pspe->pe.pde4M.Available);
		//	DbgPrint("\t\t\tD (dirty):                        %d\n", pspe->pe.pde4M.D);
		//	DbgPrint("\t\t\tdValue (packed value):            %d\n", pspe->pe.pde4M.dValue);
		//	DbgPrint("\t\t\tG (global page):                  %d\n", pspe->pe.pde4M.G);
		//	DbgPrint("\t\t\tP (Present (1=present)):          %d\n", pspe->pe.pde4M.P);
		//	DbgPrint("\t\t\tPCD (page-level cache disabled):  %d\n", pspe->pe.pde4M.PCD);
		//	DbgPrint("\t\t\tPFN (page-frame number):          %d\n", pspe->pe.pde4M.PFN);
		//	DbgPrint("\t\t\tPS (page size (0 = 4-KB page)):   %d\n", pspe->pe.pde4M.PS);
		//	DbgPrint("\t\t\tPWT (page-level write-through):   %d\n", pspe->pe.pde4M.PWT);
		//	DbgPrint("\t\t\tRW (read/write):                  %d\n", pspe->pe.pde4K.RW);
		//	DbgPrint("\t\t\tUS (user/supervisor):             %d\n", pspe->pe.pde4M.US);
		//	DbgPrint("\t\tpnpe (page not present entry): 0x%llx ->\n", pspe->pe.pnpe);
		//	DbgPrint("\t\t\tdValue (packed value):                %d\n", pspe->pe.pnpe.dValue);
		//	DbgPrint("\t\t\tP (Present (0 = not present)):        %d\n", pspe->pe.pnpe.P);
		//	DbgPrint("\t\t\tPageFile (page swapped to page file): %d\n", pspe->pe.pnpe.PageFile);
		//	DbgPrint("\t\tpte4K (page-table entry (4KB-page)): 0x%llx ->\n", pspe->pe.pte4K);
		//	DbgPrint("\t\t\tA (accessed):                     %d\n", pspe->pe.pte4K.A);
		//	DbgPrint("\t\t\tAvailable (avail. to devs):       %d\n", pspe->pe.pte4K.Available);
		//	DbgPrint("\t\t\tD (dirty):                        %d\n", pspe->pe.pte4K.D);
		//	DbgPrint("\t\t\tdValue (packed value):            %d\n", pspe->pe.pte4K.dValue);
		//	DbgPrint("\t\t\tG (global page):                  %d\n", pspe->pe.pte4K.G);
		//	DbgPrint("\t\t\tP (Present (1=present)):          %d\n", pspe->pe.pte4K.P);
		//	DbgPrint("\t\t\tPCD (page-level cache disabled):  %d\n", pspe->pe.pte4K.PCD);
		//	DbgPrint("\t\t\tPFN (page-frame number):          %d\n", pspe->pe.pte4K.PFN);
		//	DbgPrint("\t\t\tPWT (page-level write-through):   %d\n", pspe->pe.pte4K.PWT);
		//	DbgPrint("\t\t\tRW (read/write):                  %d\n", pspe->pe.pte4K.RW);
		//	DbgPrint("\t\t\tUS (user/supervisor):             %d\n", pspe->pe.pte4K.US);
		//}

		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);
		ZwUnmapViewOfSection(ZwCurrentProcess(), hSection);
		ZwClose(hSection);

		// TODO: Wrong Address for ntBase -> thus for KeServiceDescriptorTable
		unsigned long long KeServiceDescriptorTableOffset = GetSymOffset("KeServiceDescriptorTable");
		unsigned long long ntBase = GetSymOffset("ntBase");
		unsigned long long KeServiceDescriptorTable = ntBase + KeServiceDescriptorTableOffset;
		DbgPrint("[+] KeServiceDescriptorTable at: 0x%llx\n", KeServiceDescriptorTable);
		DbgPrint("[+] KeServiceDescriptorTableOffset at: 0x%llx\n", KeServiceDescriptorTableOffset);
		DbgPrint("[+] ntBase at: 0x%llx\n", ntBase);
		PHYSICAL_ADDRESS phys =  MmGetPhysicalAddress(KeServiceDescriptorTable);
		DbgPrint("[+] Physical: QuadPart: 0x%llx | HighPart: 0x%llx | LowPart: 0x%llx | u_HighPart: 0x%llx | u_LowPart: 0x%llx\n",
			phys.QuadPart, phys.HighPart, phys.LowPart, phys.u.HighPart, phys.u.LowPart);

		VirtToPhys(KeServiceDescriptorTable, 4, TRUE);

		//PVOID test = MmMapIoSpace(PML4E, 0x16, MmNonCached);
		//DbgPrint("[+] Read Physical: 0x%llx\n", *test);


	//TODO: SpyDispatcher();
	//TODO: SpyHookInitialize();
	}
	return ns;
}

// =================================================================
// DRIVER REQUEST HANDLER
// =================================================================

NTSTATUS DriverDispatcher(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	return(pDeviceObject == gpDeviceObject
		? DeviceDispatcher(gpDeviceContext, pIrp)
		: STATUS_INVALID_PARAMETER);
}

// -----------------------------------------------------------------

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	SpyHookCleanup();

	if (SymbolList != NULL)
		ExFreePool(SymbolList);

	IoDeleteSymbolicLink(&usSymbolicLinkName);
	IoDeleteDevice(gpDeviceObject);
	return;
}

// =====================================
// MEMORY ACCESS FUNCTIONS
// =====================================
BOOL SpyMemoryPageEntry(PVOID pVirtual, PSPY_PAGE_ENTRY pspe) {
	SPY_PAGE_ENTRY spe;
	BOOL fOk = FALSE;

	spe.pe = X86_PDE_ARRAY[X86_PDI(pVirtual)];
	spe.dSize = X86_PAGE_4M;
	spe.fPresent = FALSE;

	if (spe.pe.pde4M.P) {
		if (spe.pe.pde4M.PS) {
			fOk = spe.fPresent = TRUE;
		} else {
			spe.pe = X86_PTE_ARRAY[X86_PAGE(pVirtual)];
			spe.dSize = X86_PAGE_4K;
			if (spe.pe.pte4K.P) {
				fOk = spe.fPresent = TRUE;
			} else {
				fOk = (spe.pe.pnpe.PageFile != 0);
			}
		}
	}
	if (pspe != NULL) *pspe = spe;
	return fOk;
}

NTSTATUS DeviceDispatcher(PDEVICE_CONTEXT pDeviceContext, PIRP pIrp) {
	PIO_STACK_LOCATION pisl;
	DWORD dInfo = 0;
	NTSTATUS ns = STATUS_NOT_IMPLEMENTED;

	pisl = IoGetCurrentIrpStackLocation(pIrp);

	switch (pisl->MajorFunction) {
		case IRP_MJ_CREATE:
		case IRP_MJ_CLEANUP:
		case IRP_MJ_CLOSE:
		{
			ns = STATUS_SUCCESS;
			break;
		}
		case IRP_MJ_DEVICE_CONTROL:
		{
			ns = SpyDispatcher(pDeviceContext,

				pisl->Parameters.DeviceIoControl
				.IoControlCode,

				pIrp->AssociatedIrp.SystemBuffer,
				pisl->Parameters.DeviceIoControl
				.InputBufferLength,

				pIrp->AssociatedIrp.SystemBuffer,
				pisl->Parameters.DeviceIoControl
				.OutputBufferLength,
				&dInfo);
			break;
		}
	}
	pIrp->IoStatus.Status = ns;
	pIrp->IoStatus.Information = dInfo;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ns;
}

NTSTATUS SpyDispatcher(	PDEVICE_CONTEXT pDeviceContext,
						DWORD dCode,
						PVOID pInput,
						DWORD dInput,
						PVOID pOutput,
						DWORD dOutput,
						PDWORD pdInfo) {
	SPY_MEMORY_BLOCK smb;
	SPY_PAGE_ENTRY spe;
	SPY_CALL_INPUT sci;
	PHYSICAL_ADDRESS pa;
	DWORD dValue, dCount;
	BOOL fReset, fPause, fFilter, fLine;
	PVOID pAddress;
	PBYTE pbName;
	HANDLE hObject;
	NTSTATUS ns = STATUS_INVALID_PARAMETER;

	MUTEX_WAIT(pDeviceContext->kmDispatch);

	*pdInfo = 0;

	switch (dCode) {
	// TODO: -----
	//case SPY_IO_VERSION_INFO: {

	//}
	}

	return STATUS_SUCCESS;
}

// =================================================================
// HOOK PROTOCOL MANAGEMENT (WRITE)
// =================================================================

void SpyWriteReset(PSPY_PROTOCOL psp) {
	KeQuerySystemTime(&psp->sh.liStart);

	psp->sh.dRead		= 0;
	psp->sh.dWrite		= 0;
	psp->sh.dCalls		= 0;
	psp->sh.dHandles	= 0;
	psp->sh.dName		= 0;
	return;
}

NTSTATUS SpyHookRemove(BOOL fReset, PDWORD pdCount) {
	LARGE_INTEGER liDelay;
	BOOL fInUse;
	DWORD i;
	DWORD n = 0;
	NTSTATUS ns = STATUS_HV_INVALID_DEVICE_STATE;

	if (gfSpyHookState) {
		n = SpyHookExchange();
		if (fReset)SpyHookReset();

		do {
			for (i = 0; i < SPY_CALLS; i++) {
				if (fInUse = gpDeviceContext->SpyCalls[i].fInUse)
					break;
			}
			liDelay.QuadPart = -1000000;
			KeDelayExecutionThread(KernelMode, FALSE, &liDelay);
		} while (fInUse);

		ghSpyHookThread = 0;

		ns = STATUS_SUCCESS;
	}
	*pdCount = n;
	return ns;
}

DWORD SpyHookExchange(void) {
	PNTPROC ServiceTable;
	BOOL fPause;
	DWORD i;
	DWORD n = 0;

	fPause = SpyHookPause(TRUE);
	ServiceTable = KeServiceDescriptorTable->ntoskrnl.ServiceTable;

	for (i = 0; i < SDT_SYMBOLS_MAX; i++) {
		if (aSpyHooks[i].pbFormat != NULL) {
			InterlockedExchange((PLONG)ServiceTable + 1, (LONG)aSpyHooks[i].Handler);
			n++;
		}
	}
	gfSpyHookState = !gfSpyHookState;
	SpyHookPause(fPause);
	return n;
}

BOOL SpyHookPause(BOOL fPause) {
	BOOL fPause1 = (BOOL)InterlockedExchange((PLONG)&gfSpyHookPause, (LONG)fPause);

	if (!fPause)SpyHookReset();
	return fPause1;
}

NTSTATUS SpyHookWait(void)
{
	return MUTEX_WAIT(gpDeviceContext->kmProtocol);
}

void SpyHookReset(void) {
	SpyHookWait();
	SpyWriteReset(&gpDeviceContext->SpyProtocol);
	SpyHookRelease();
	return;
}

LONG SpyHookRelease(void)
{
	return MUTEX_RELEASE(gpDeviceContext->kmProtocol);
}

void SpyHookCleanup(void) {
	DWORD dCount;

	SpyHookRemove(FALSE, &dCount);
	return;
}