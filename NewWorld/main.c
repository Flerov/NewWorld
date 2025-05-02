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

typedef struct _INIT {
	CHAR identifier[4];
	DWORD NtBaseOffset;
	DWORD KPROCDirectoryTableBaseOffset;
	DWORD EPROCActiveProcessLinksOfsset;
	DWORD EPROCUniqueProcessIdOffset;
} INIT, *PINIT;

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
		return 0;  // Return 0 instead of NULL for a UINT64 return type

	// Calculate the address after the INIT structure
	PSYMBOL syms = (PSYMBOL)((PINIT)SymbolList + sizeof(INIT));  // Add 1 to move past the INIT structure

	// Calculate maximum symbols based on remaining size
	size_t maxSymCount = (SymsViewSize - sizeof(INIT)) / sizeof(SYMBOL);

	for (size_t i = 0; i < maxSymCount; i++) {  // Use < instead of <= to avoid overflow
		if (strcmp(syms[i].name, str) == 0) {
			return syms[i].offset;
		}
	}

	return 0;  // Return 0 if symbol not found
}

INIT gInit = { 0 };
BOOL InitData() {
	if (SymbolList == NULL)
		return FALSE;

	PINIT initPos = (PINIT)SymbolList;

	// Compare as 4 separate characters or use a proper string comparison
	if (initPos->identifier[0] == 'I' &&
		initPos->identifier[1] == 'N' &&
		initPos->identifier[2] == 'I' &&
		initPos->identifier[3] == 'T') {

		gInit = *initPos;  // Copy the structure
		return TRUE;
	}

	return FALSE;
}

PEPROCESS GetProcess(UINT32 pid, unsigned long long eprocUniqueProcessId, unsigned long long eprocActiveProcessLinks) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PUINT32 CurrentPID = (PUINT32)((ULONG_PTR)CurrEProc + eprocUniqueProcessId);
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	do {
		if (*(UINT32*)CurrentPID == pid) {
			PEPROCESS targetProcess = (PEPROCESS)CurrEProc;
			DbgPrint("[+] PEPROCESS Target Process: 0x%llx\n", targetProcess);
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

PEPROCESS GetProcessByName(
	const char* FileName,
	unsigned long long eprocImageFileNameOffset,
	unsigned long long eprocActiveProcessLinks) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	PCHAR CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
	size_t FileNameSize = (strlen(FileName) > 15) ? 15 : strlen(FileName);
	do {
		if (!MmIsAddressValid(CurrEProc)) {
			DbgPrint("[-] Invalid EPROCESS address: 0x%llx\n", CurrEProc);
			return 0x0;
		}
		if (memcmp(FileName, CurrentImageName, FileNameSize) == 0)
			return CurrEProc;
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
	return 0x0;
}

PVOID GetDirectoryTableBaseByName(
	const char* FileName,
	unsigned long long eprocImageFileNameOffset,
	unsigned long long eprocActiveProcessLinks,
	unsigned long long kprocDirectoryTableBase) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	PCHAR CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
	size_t FileNameSize = (strlen(FileName) > 15) ? 15 : strlen(FileName);
	do {
		if (!MmIsAddressValid(CurrEProc)) {
			DbgPrint("[-] Invalid EPROCESS address: 0x%llx\n", CurrEProc);
			return 0x0;
		}
		if (memcmp(FileName, CurrentImageName, FileNameSize) == 0) {
			PVOID* test = (unsigned long long)CurrEProc + kprocDirectoryTableBase;
			return *test;
			//return (PVOID*)((unsigned long long)CurrEProc + kprocDirectoryTableBase);
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
	return 0x0;
}

PHYSICAL_ADDRESS OrigPhys = { 0 };
unsigned long long OrigVal = 0x0;
VOID ChangeRef(
	unsigned long long SourceVA, PEPROCESS SourceProcess, unsigned long long SourceCR3,
	unsigned long long TargetVA, PEPROCESS TargetProcess, unsigned long long TargetCR3) {

	unsigned long long TargetPFN = 0x0;
	KAPC_STATE ApcState;
	NTSTATUS status;
	SIZE_T numRec = 0;

	MM_COPY_ADDRESS PhysPML4 = { 0 }; // Physical Page Map Level 4
	MM_COPY_ADDRESS PhysPDPT = { 0 }; // Physical Page Directory Pointer Table
	MM_COPY_ADDRESS PhysPD = { 0 };   // Physical Page Directory
	MM_COPY_ADDRESS PhysPage = { 0 }; // Physical Page Table
	MM_COPY_ADDRESS Phys = { 0 };     // Physical

	unsigned long long PML4Offset;
	unsigned long long PDPTOffset;
	unsigned long long PDOffset;
	unsigned long long PTOffset;
	unsigned long long MaskOffset;

	unsigned long long tmp = 0x0;
	unsigned long long pml4e = 0x0; // Page Map Level 4 Entry (Pointer)
	unsigned long long pdpte = 0x0; // Page Directory Pointer Table Entry (Pointer)
	unsigned long long pde = 0x0;   // Page Directory Entry (Pointer)
	unsigned long long pte = 0x0;   // Page Table Entry (Pointer)
	unsigned long long physAdr = 0x0; // unused

	PML4E* PML4ERaw = 0x0; // Page Map Level 4 Entry
	PDPTE* PDPTERaw = 0x0; // Page Directory Pointer Table Entry
	PDE* PDERaw = 0x0; // Page Directory Entry
	PTE* PTERaw = 0x0; // Page Table Entry
	PHYSICAL_1GB* PHYSRaw1GB = 0x0; // Huge Page
	PHYSICAL_2MB* PHYSRaw2MB = 0x0; // Large Page
	PHYSICAL_4KB* PHYSRaw4KB = 0x0; // Page

	// Target Process
	DbgPrint("Get for Target\n");
	// Extract the PFN
	KeStackAttachProcess(TargetProcess, &ApcState);
	//MDL* pMdlTarget = IoAllocateMdl(TargetVA, sizeof(TargetVA), FALSE, FALSE, NULL);
	//MmProbeAndLockPages(pMdlTarget, UserMode, IoWriteAccess);

	PML4Offset = (TargetVA & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	PDPTOffset = (TargetVA & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	PDOffset = (TargetVA & 0x3FE00000) >> 0x15;       // Page Directory Offset
	PTOffset = (TargetVA & 0x1FF000) >> 0x0C;         // Page Table Offset
	MaskOffset = (TargetVA & 0xFFF);               // Physical Offset

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = TargetCR3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		PDERaw = (PDE*)&pde;
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		DbgPrint("Got PT-Base: 0x%llx\n", TargetPFN);
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			TargetPFN = pte;
			pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits
			//TargetPFN = pde >> 0xC; // Get the PFN
			PTERaw = (PTE*)&pte;
			PHYSRaw4KB = (PHYSICAL_4KB*)&pte;
			//TargetPFN = PHYSRaw4KB->Value;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
	}
	//MmUnlockPages(pMdlTarget);
	//IoFreeMdl(pMdlTarget);
	KeUnstackDetachProcess(&ApcState);

	// Source Process
	DbgPrint("Get for Source\n");
	KeStackAttachProcess(SourceProcess, &ApcState);
	//MDL* pMdlSource = IoAllocateMdl(SourceVA, sizeof(SourceVA), FALSE, FALSE, NULL);
	//MmProbeAndLockPages(pMdlSource, UserMode, IoReadAccess);

	PML4Offset = (SourceVA & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	PDPTOffset = (SourceVA & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	PDOffset = (SourceVA & 0x3FE00000) >> 0x15;       // Page Directory Offset
	PTOffset = (SourceVA & 0x1FF000) >> 0x0C;         // Page Table Offset
	//MaskOffset = (SourceVA & 0x1FFFFF);               // Physical Offset
	MaskOffset = (SourceVA & 0xFFF);               // Physical Offset

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = SourceCR3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			//status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			//pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits

			// Todo Why cant I do Copy Memory twice on the same Physical???
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&physAdr, Phys, sizeof(physAdr), MM_COPY_MEMORY_PHYSICAL, &numRec);
			OrigPhys.QuadPart = Phys.PhysicalAddress.QuadPart;
			OrigVal = physAdr;
			physAdr = physAdr & 0xFFFFFFFFFFFF; // Mask out the upper bits
			PTERaw = (PTE*)&physAdr;
			PHYSRaw4KB = (PHYSICAL_4KB*)&physAdr;
			//PTERaw = (PTE*)&pte;
			//PHYSRaw4KB = (PHYSICAL_4KB*)&pte;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
	}
	// Make sure the Section is not paged-out
	DbgPrint("Test for Change\n");
	DbgPrint("TargetPFN: 0x%llx\n", TargetPFN);
	DbgPrint("SourceVA: 0x%llx\n", SourceVA);
	if (TargetPFN != 0x0 && PTERaw != 0x0) {
		PTE* temp = MmGetVirtualForPhysical(Phys.PhysicalAddress);
		DbgPrint("VirtualForPhysical at: 0x%llx\n", temp);
		DbgPrint("Changing PFN to TargetPFN: 0x%llx - 0x%llx\n", temp->Value, TargetPFN);
		// preserve the upper original bytes, since we have them masked out in TargetPFN and we dont want to overwrite with 0's
		//PVOID* temp2 = (PVOID*)((unsigned long long)temp - 0x4);
		//DbgPrint("temp2 is: 0x%llx\n", temp2);
		//DbgPrint("temp2 has: 0x%llx\n", *temp2);
		//PVOID* temp3 = (unsigned long long)*temp2 >> 0xC;
		//DbgPrint("PFN is: 0x%llx\n", temp3);
		//DbgPrint("TargetPFN: 0x%llx\n", TargetPFN);
		memcpy(temp, &TargetPFN, sizeof(TargetPFN)); // the size should be correct
		DbgPrint("CHANGED\n");
		__invlpg(SourceVA);
		KeUnstackDetachProcess(&ApcState);
		return;
		//KeUnstackDetachProcess(&ApcState);
		//VirtToPhys(SourceVA, SourceProcess, SourceCR3, TRUE);
	}
	else {
		DbgPrint("[-] PTERaw is NULL\n");
		KeUnstackDetachProcess(&ApcState);
	}
	DbgPrint("Returning\n");
	return;
}

VOID VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log) {
	KAPC_STATE ApcState;
	NTSTATUS status;
	SIZE_T numRec = 0;
	MM_COPY_ADDRESS PhysPML4 = { 0 }; // Physical Page Map Level 4
	MM_COPY_ADDRESS PhysPDPT = { 0 }; // Physical Page Directory Pointer Table
	MM_COPY_ADDRESS PhysPD = { 0 };   // Physical Page Directory
	MM_COPY_ADDRESS PhysPage = { 0 }; // Physical Page Table
	MM_COPY_ADDRESS Phys = { 0 };     // Physical

	unsigned long long PML4Offset = (addr & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	unsigned long long PDPTOffset = (addr & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	unsigned long long PDOffset = (addr & 0x3FE00000) >> 0x15;       // Page Directory Offset
	unsigned long long PTOffset = (addr & 0x1FF000) >> 0x0C;         // Page Table Offset
	unsigned long long MaskOffset = (addr & 0x1FFFFF);               // Physical Offset

	unsigned long long tmp = 0x0;
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

	KeStackAttachProcess(TargetProcess, &ApcState);
	MDL* pMdl = IoAllocateMdl(addr, 4096, FALSE, FALSE, NULL);
	MmProbeAndLockPages(pMdl, UserMode, IoReadAccess);

	// walk PML4 -> Physical
	PhysPML4.PhysicalAddress.QuadPart = cr3 + (PML4Offset * 0x08);
	status = MmCopyMemory(&pml4e, PhysPML4, sizeof(pml4e), MM_COPY_MEMORY_PHYSICAL, &numRec); // sizeof(pml4e) / 2 bei allen
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PML4ERaw->PageFrameNumber instead it matches to PhysPML4.PhysicalAddress.QuadPart
	pml4e = pml4e & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PML4ERaw = (PML4E*)&pml4e;

	PhysPDPT.PhysicalAddress.QuadPart = (pml4e & 0xFFFFF000) + (PDPTOffset * 0x08);
	status = MmCopyMemory(&pdpte, PhysPDPT, sizeof(pdpte), MM_COPY_MEMORY_PHYSICAL, &numRec);
	// TODO: The PFN of !vtop output for PML4E does not match with the pfn of PDPTERaw->PageFrameNumber instead it matches to PhysPDPT.PhysicalAddress.QuadPart
	pdpte = pdpte & 0xFFFFFFFFFFFF; // Mask out the upper bits
	PDPTERaw = (PDPTE*)&pdpte;

	if (PDPTERaw->PageSize == 0) {
		// 1 = Maps a 1GB page, 0 = Points to a page directory.
		PhysPD.PhysicalAddress.QuadPart = (pdpte & 0xFFFFF000) + (PDOffset * 0x08);
		status = MmCopyMemory(&pde, PhysPD, sizeof(pde), MM_COPY_MEMORY_PHYSICAL, &numRec);
		pde = pde & 0xFFFFFFFFFFFF; // Mask out the upper bits
		PDERaw = (PDE*)&pde;
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits
			PTERaw = (PTE*)&pte;
			PHYSRaw4KB = (PHYSICAL_4KB*)&pte;
		}
		else {
			PHYSRaw2MB = (PHYSICAL_2MB*)&pde;
		}
	}
	else {
		PHYSRaw1GB = (PHYSICAL_1GB*)&pdpte;
	}
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);

	if (log) {
		DbgPrint("[+] cr3: 0x%llx\n", cr3);
		DbgPrint("[+] PML4E Raw - Virtual: 0x%llx\n"
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
			PhysPML4.PhysicalAddress.QuadPart,
			PML4ERaw->Accessed, PML4ERaw->ExecuteDisable, PML4ERaw->PageCacheDisable,
			PML4ERaw->PageFrameNumber, PML4ERaw->PageSize, PML4ERaw->PageWriteThrough,
			PML4ERaw->Present, PML4ERaw->ProtectionKey, PML4ERaw->ReadWrite, PML4ERaw->UserSupervisor, PML4ERaw->Value);
		DbgPrint("[+] PDPTE Raw - Virtual: 0x%llx\n"
			"\t[*] Accessed: %llu\n"
			"\t[*] ExecuteDisable: %llu\n"
			"\t[*] PageCacheDisable: %llu\n"
			"\t[*] PageSize: %llu\n"
			"\t[*] PageWriteThrough: %llu\n"
			"\t[*] Present: %llu\n"
			"\t[*] PAT: %llu\n"
			"\t[*] ReadWrite: %llu\n"
			"\t[*] UserSupervisor: %llu\n"
			"\t[*] Value: %llx\n"
			"\t[*] PageFrameNumber: %llx\n",
			PhysPDPT.PhysicalAddress.QuadPart,
			(unsigned long long)PDPTERaw->Accessed,
			(unsigned long long)PDPTERaw->ExecuteDisable,
			(unsigned long long)PDPTERaw->PageCacheDisable,
			(unsigned long long)PDPTERaw->PageSize,
			(unsigned long long)PDPTERaw->PageWriteThrough,
			(unsigned long long)PDPTERaw->Present,
			PDPTERaw->PageSize ? (unsigned long long)PDPTERaw->PAT : 0,
			(unsigned long long)PDPTERaw->ReadWrite,
			(unsigned long long)PDPTERaw->UserSupervisor,
			PDPTERaw->Value,
			(unsigned long long)PDPTERaw->PageFrameNumber);
		DbgPrint("[*] PDPTE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
			PDPTERaw->PageSize ? (int)PDPTERaw->PAT : -1,
			(int)PDPTERaw->PageCacheDisable,
			(int)PDPTERaw->PageWriteThrough,
			PDPTERaw->PageSize ?
			((unsigned long long)PDPTERaw->PAT << 2) | ((unsigned long long)PDPTERaw->PageCacheDisable << 1) | (unsigned long long)PDPTERaw->PageWriteThrough :
			(unsigned long long) - 1,
			IA32_PAT_MSR);
		if (PDERaw != 0x0) {
			DbgPrint("[+] PDE Raw - Virtual: 0x%llx\n"
				"\t[*] Accessed: %llx\n"
				"\t[*] Ignored1: %llx\n"
				"\t[*] Ignored2: %llx\n"
				"\t[*] ExecuteDisable: %llx\n"
				"\t[*] PageCacheDisable: %llx\n"
				"\t[*] PageFrameNumber: %llx\n"
				"\t[*] PageSize: %llx\n"
				"\t[*] PageWriteThrough: %llx\n"
				"\t[*] PAT: %llx\n"
				"\t[*] Present: %llx\n"
				"\t[*] ReadWrite: %llx\n"
				"\t[*] Reserved: %llx\n"
				"\t[*] UserSupervisor: %llx\n"
				"\t[*] Ignored3: %llx\n"
				"\t[*] Value: %llx\n",
				PhysPD.PhysicalAddress.QuadPart,
				PDERaw->Accessed, PDERaw->AVL, PDERaw->Ignored2,
				PDERaw->ExecuteDisable, PDERaw->PageCacheDisable, PDERaw->PageFrameNumber,
				PDERaw->PageSize, PDERaw->PageWriteThrough, PDERaw->PAT,
				PDERaw->Present, PDERaw->ReadWrite, PDERaw->Reserved,
				PDERaw->UserSupervisor, PDERaw->Ignored3, PDERaw->Value);
			DbgPrint("[*] PDE PAT-Index -> PAT: %d | PCD: %d | PWT: %d -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
				PDERaw->PAT, PDERaw->PageCacheDisable, PDERaw->PageWriteThrough,
				(PDERaw->PAT << 2) | (PDERaw->PageCacheDisable << 1) | PDERaw->PageWriteThrough,
				IA32_PAT_MSR);
			if (PTERaw != 0x0) {
				// For lines where PTERaw->PageAccessType is referenced:
				DbgPrint("[+] PTE Raw - Virtual: 0x%llx\n"
					"\t[*] Accessed: %llu\n"
					"\t[*] Dirty: %llu\n"
					"\t[*] ExecuteDisable: %llu\n"
					"\t[*] Global: %llu\n"
					"\t[*] PAT: %llu\n"
					"\t[*] PageCacheDisable: %llu\n"
					"\t[*] PageFrameNumber: %llu\n"
					"\t[*] PageWriteThrough: %llu\n"
					"\t[*] Present: %llu\n"
					"\t[*] ProtectionKey: %llu\n"
					"\t[*] ReadWrite: %llu\n"
					"\t[*] UserSupervisor: %llu\n"
					"\t[*] Value: %llx\n",
					PhysPage.PhysicalAddress.QuadPart,
					PTERaw->Accessed, PTERaw->Dirty, PTERaw->ExecuteDisable, PTERaw->Global, PTERaw->PAT, PTERaw->PageCacheDisable, PTERaw->PageFrameNumber, PTERaw->PageWriteThrough, PTERaw->Present,
					PTERaw->ProtectionKey, PTERaw->ReadWrite, PTERaw->UserSupervisor, PTERaw->Value);
				DbgPrint("[*] PTE PAT-Index -> PAT: %llu | PCD: %llu | PWT: %llu -> Index: %llx | IA32_PAT_MSR: 0x%llx\n",
					PTERaw->PAT, PTERaw->PageCacheDisable, PTERaw->PageWriteThrough,
					(PTERaw->PAT << 2) | (PTERaw->PageCacheDisable << 1) | PTERaw->PageWriteThrough, IA32_PAT_MSR);
				DbgPrint("[+] PHYS 4KB-\n"
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
	KeUnstackDetachProcess(&ApcState);
	return;
}

UNICODE_STRING* GetFileObjectFromVADLeaf(unsigned long long Leaf, DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName) {
	// Check if Leaf is NULL first
	if (Leaf == 0) {
		return NULL;
	}

	unsigned long long SubsectionPtr = *(PVOID*)(Leaf + MMVADSubsection);
	// MmIsAddressValid is much faster than try-except and achieves similar safety
	if (!MmIsAddressValid((PVOID)SubsectionPtr)) {
		return NULL;
	}

	unsigned long long ControlArea = *(PVOID*)(SubsectionPtr);
	if (!MmIsAddressValid((PVOID)ControlArea)) {
		return NULL;
	}

	unsigned long long FilePointer = (PVOID*)(ControlArea + MMVADCAFilePointer);
	if (!MmIsAddressValid((PVOID)FilePointer)) {
		return NULL;
	}

	unsigned long long FileObject = *(PVOID*)FilePointer;
	if (!MmIsAddressValid((PVOID)FileObject)) {
		return NULL;
	}

	// Apply mask to FileObject
	FileObject = FileObject - (FileObject & 0xF);
	if (!MmIsAddressValid((PVOID)(FileObject + FILEOBJECTFileName))) {
		return NULL;
	}

	UNICODE_STRING* FileName = (UNICODE_STRING*)(FileObject + FILEOBJECTFileName);
	// Additional validation on the UNICODE_STRING structure
	if (!MmIsAddressValid(FileName->Buffer)) {
		return NULL;
	}

	return FileName;
}

ULONG GetRandomAddress(ULONG Start, ULONG End) {
	LARGE_INTEGER perfCounter;
	KeQueryPerformanceCounter(&perfCounter);
	ULONG Seed = (ULONG)perfCounter.LowPart;
	ULONG RandomAddress = Start + (RtlRandomEx(&Seed) % (End - Start + 1));
	RandomAddress &= ~0x3; // Ensure the address is aligned to a 4-byte boundary
	return RandomAddress;
}
unsigned long long RandAddr = 0x0;
VOID WalkVADRecursive(PVOID VADNode, unsigned long StartingVpnOffset, DWORD EndingVpnOffset,
	DWORD Left, DWORD Right, int Level,
	PULONG TotalVADs, PULONG TotalLevels, PULONG MaxDepth,
	DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName,
	unsigned long long targetAdr) {
	// If node is NULL, return
	if (VADNode == NULL) {
		return;
	}
	// Update statistics
	(*TotalVADs)++;
	(*TotalLevels) += Level;
	if (Level > *MaxDepth) {
		*MaxDepth = Level;
	}

	// Get node information
	unsigned long long Vpn;
	unsigned long long VpnStart;
	unsigned long long VpnEnd;
	unsigned long long VpnHigh;
	unsigned long long VpnHighPart0;
	unsigned long long VpnHighPart1;
	unsigned long long StartingVpn;
	unsigned long long EndingVpn;
	Vpn = *(PVOID*)((unsigned long long)VADNode + StartingVpnOffset);
	VpnStart = Vpn & 0xFFFFFFFF;
	VpnEnd = (Vpn >> 32) & 0xFFFFFFFF;

	VpnHigh = *(PVOID*)((unsigned long long)VADNode + 0x20); // StartingVpnHigh
	VpnHighPart0 = VpnHigh & 0xFF; // Mask to get low part
	VpnHighPart1 = (VpnHigh >> 8) & 0xFF;
	VpnHighPart0 = VpnHighPart0 << 32;
	VpnHighPart1 = VpnHighPart1 << 32;

	StartingVpn = VpnStart | VpnHighPart0;
	EndingVpn = VpnEnd | VpnHighPart1;

	// Check if targetAdr is within the range of this VAD
	BOOLEAN isTargetInRange = FALSE;
	//if (targetAdr != 0) {
	//	// Convert the address to a VPN (Virtual Page Number) for comparison
	//	// A page is typically 4KB (0x1000), so shift right by 12 bits
	//	unsigned long long targetVpn = targetAdr >> 12;
	//	isTargetInRange = (targetVpn >= StartingVpn && targetVpn <= EndingVpn);
	//}

	UNICODE_STRING* FileName = GetFileObjectFromVADLeaf(VADNode, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName);

	// Print current node with fixed width formatting
	// Add indicator if this range contains the target address
	if (FileName == NULL) {
		DbgPrint("%-10d 0x%p          0x%010I64x     0x%010I64x     %s\n",
			Level,
			VADNode,
			StartingVpn,
			EndingVpn,
			isTargetInRange ? "** CONTAINS TARGET **" : "");
	}
	else {
		DbgPrint("%-10d 0x%p          0x%010I64x     0x%010I64x     %wZ     %s\n",
			Level,
			VADNode,
			StartingVpn,
			EndingVpn,
			FileName,
			isTargetInRange ? "** CONTAINS TARGET **" : "");
		//if (_wcsicmp(FileName->Buffer, L"\\Windows\\System32\\ntmarta.dll") == 0) {
		if (_wcsicmp(FileName->Buffer, L"\\Windows\\System32\\notepad.exe") == 0) {
			//RandAddr = GetRandomAddress(StartingVpn->LowPart, EndingVpn->LowPart);
			RandAddr = StartingVpn * 0x1000;
			DbgPrint("Random Address at fixed point: 0x%llx\n", RandAddr);
		}
	}

	//if (*TotalVADs == 55) {
	//	RandAddr = GetRandomAddress(StartingVpn->LowPart, EndingVpn->LowPart);
	//	RandAddr = StartingVpn->LowPart;
	//	DbgPrint("Random Address at fixed point: 0x%lx\n", RandAddr);
	//}

	// Get left and right children
	PVOID LeftChild = *(PVOID*)((ULONG_PTR)VADNode + Left);
	PVOID RightChild = *(PVOID*)((ULONG_PTR)VADNode + Right);

	// Recursively traverse left subtree first (smaller addresses)
	WalkVADRecursive(LeftChild, StartingVpnOffset, EndingVpnOffset, Left, Right,
		Level + 1, TotalVADs, TotalLevels, MaxDepth,
		MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);

	// Recursively traverse right subtree last (larger addresses)
	WalkVADRecursive(RightChild, StartingVpnOffset, EndingVpnOffset, Left, Right,
		Level + 1, TotalVADs, TotalLevels, MaxDepth,
		MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);
}

unsigned long long WalkLoadedModulesInTargetProcess(
	unsigned long long pTargetEProcess, WCHAR* pTargetName, DWORD PEBOffset, DWORD PEBLdrOffset,
	DWORD LdrListHeadOffset, DWORD InLoadOrderModuleListOffset,
	DWORD LdrBaseDllNameOffset, DWORD LdrBaseDllBaseOffset) {
	KAPC_STATE ApcState;
	unsigned long long PEB = *(PVOID*)(pTargetEProcess + PEBOffset);
	KeStackAttachProcess(pTargetEProcess, &ApcState);
	//D3COLD_AUX_POWER_AND_TIMING_INTERFACE* PEBLdr = PEB + PEBLdrOffset; // what is this?
	unsigned long long PEBLdr = *(PVOID*)(PEB + PEBLdrOffset);
	LIST_ENTRY* LdrListHead = (PEBLdr + LdrListHeadOffset) - 0x10;
	LIST_ENTRY* pCurrentEntry = LdrListHead;
	LIST_ENTRY* pNextEntry = LdrListHead->Flink;
	unsigned long long ret = 0x0;
	do {
		unsigned long long LdrEntry = (unsigned long long)pCurrentEntry - InLoadOrderModuleListOffset;
		unsigned long long BaseDllName = LdrEntry + LdrBaseDllNameOffset;
		UNICODE_STRING* pBaseDllName = (UNICODE_STRING*)BaseDllName;
		// Actual format of pBaseDllName->Buffer is: "C:\Windows\SYSTEM32\name.dll"
		// Find the last backslash to get just the filename
		for (int i = (pBaseDllName->Length / sizeof(WCHAR)) - 1; i >= 0; i--) {
			if (pBaseDllName->Buffer[i] == L'\\') {
				UNICODE_STRING truncatedName;
				truncatedName.Buffer = &pBaseDllName->Buffer[i+1];
				truncatedName.Length = pBaseDllName->Length - ((i+1) * sizeof(WCHAR));
				truncatedName.MaximumLength = pBaseDllName->MaximumLength;
				//if (_wcsicmp(truncatedName.Buffer, L"ntmarta.dll") == 0) {
				DbgPrint("TruncatedName: %wZ\n", &truncatedName);
				if (_wcsicmp(truncatedName.Buffer, L"notepad.exe") == 0) {
				//if (_wcsicmp(truncatedName.Buffer, pTargetName) == 0) {
					DbgPrint("Target: %wZ found\n", truncatedName.Buffer);
					DbgPrint("LDR_DATA_TABLE_ENTRY: 0x%llx\n", LdrEntry);
					DbgPrint("DllBase: 0x%llx\n", LdrEntry + LdrBaseDllBaseOffset);
					ret = *(PVOID*)(LdrEntry + LdrBaseDllBaseOffset);
					KeUnstackDetachProcess(&ApcState);
					return ret;
				}
				break;
			}
		}
		pNextEntry = (LIST_ENTRY*)pCurrentEntry->Flink;
		pCurrentEntry = pNextEntry;
	} while (pCurrentEntry != (LIST_ENTRY*)LdrListHead);
	KeUnstackDetachProcess(&ApcState);
	return;
}

VOID WalkVAD(PEPROCESS TargetProcess, DWORD VADRootOffset, DWORD StartingVpnOffset, DWORD EndingVpnOffset, DWORD Left, DWORD Right,
	DWORD MMVADSubsection, DWORD MMVADControlArea, DWORD MMVADCAFilePointer, DWORD FILEOBJECTFileName, unsigned long long targetAdr) {
	// Get the VAD root from the process
	PVOID* pVADRoot = (PVOID*)((ULONG_PTR)TargetProcess + VADRootOffset);
	if (!MmIsAddressValid(*pVADRoot)) {
		DbgPrint("[-] VAD tree is empty | *pVADRoot: 0x%llx -> TargetProcess: 0x%llx + VADRootOffset: 0x%lx\n", *pVADRoot, TargetProcess, VADRootOffset);
		return;
	}

	// Print header with consistent column widths
	DbgPrint("\nLevel      VADNode                StartingVpn        EndingVpn          FileName\n");
	DbgPrint("-----      -------                -----------        ---------          --------\n");

	// Variables to track statistics
	ULONG totalVADs = 0;
	ULONG totalLevels = 0;
	ULONG maxDepth = 0;

	// Call recursive function with statistics tracking - passing the targetAdr
	WalkVADRecursive(*pVADRoot, StartingVpnOffset, EndingVpnOffset, Left, Right, 1,
		&totalVADs, &totalLevels, &maxDepth, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);

	// Calculate and print statistics
	ULONG avgLevel = (totalVADs > 0) ? totalLevels / totalVADs : 0;
	ULONG avgLevelFrac = (totalVADs > 0) ? ((totalLevels * 100) / totalVADs) % 100 : 0;
	DbgPrint("Total VADs: %lu, average level: %lu.%02lu, maximum depth: %lu\n\n",
		totalVADs, avgLevel, avgLevelFrac, maxDepth);
}

PEPROCESS globalSourceProcess = NULL;
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
		}

		MmUnlockPages(pMdl);
		IoFreeMdl(pMdl);
		ZwUnmapViewOfSection(ZwCurrentProcess(), hSection);
		ZwClose(hSection);

		if (!InitData()) {
			DbgPrint("[-] Initialization failed!\n");
			return STATUS_SUCCESS;
		}

		// TODO: Use RTL_HASHTABLE instead
		unsigned long long sourceVA = GetSymOffset("SourceVA");
		DWORD sourcePID = GetSymOffset("SourcePID");
		unsigned long long mmPfnDatabase = GetSymOffset("MmPfnDatabase");
		unsigned long long eprocUniqueProcessId = GetSymOffset("eprocUniqueProcessId");
		unsigned long long eprocActiveProcessLinks = GetSymOffset("eprocActiveProcessLinks");
		unsigned long long kprocDirectoryTableBase = GetSymOffset("kprocDirectoryTableBase");
		unsigned long long KeServiceDescriptorTableOffset = GetSymOffset("KeServiceDescriptorTable");
		unsigned long long ntBase = GetSymOffset("ntBase");
		unsigned long long KeServiceDescriptorTable = ntBase + KeServiceDescriptorTableOffset;
		unsigned long long adr = GetSymOffset("SymbolsAddr");
		DWORD pid = GetSymOffset("PID");

		DWORD VADRootOffset = GetSymOffset("VADRoot");
		DWORD StartingVpnOffset = GetSymOffset("StartingVpn");
		DWORD EndingVpnOffset = GetSymOffset("EndingVpn");
		DWORD Left = GetSymOffset("Left");
		DWORD Right = GetSymOffset("Right");

		DWORD MMVADSubsectionOffset = GetSymOffset("MMVADSubsection");
		DWORD MMVADControlAreaOffset = GetSymOffset("MMVADControlArea");
		DWORD MMVADCAFilePointerOffset = GetSymOffset("MMVADCAFilePointer");
		DWORD FILEOBJECTFileNameOffset = GetSymOffset("FILEOBJECTFileName");

		DWORD EPROCImageFileNameOffset = GetSymOffset("EPROCImageFileName");

		DbgPrint("[+] sourceVA at: 0x%llx\n", sourceVA);
		DbgPrint("[+] sourcePID at: %d\n", sourcePID);

		PHYSICAL_ADDRESS phys =  MmGetPhysicalAddress(KeServiceDescriptorTable);
		DbgPrint("[+] Physical: QuadPart: 0x%llx | HighPart: 0x%llx | LowPart: 0x%llx | u_HighPart: 0x%llx | u_LowPart: 0x%llx\n",
			phys.QuadPart, phys.HighPart, phys.LowPart, phys.u.HighPart, phys.u.LowPart);

		unsigned long long sourceCR3 = GetDirectoryTableBase(sourcePID, eprocUniqueProcessId, eprocActiveProcessLinks, kprocDirectoryTableBase);
		PEPROCESS pSourceEProcess = GetProcess(sourcePID, eprocUniqueProcessId, eprocActiveProcessLinks);

		DbgPrint("[+] sourcePID: %d | sourceCR3 at: 0x%llx\n", sourcePID, sourceCR3);

		unsigned long long targetCR3 = GetDirectoryTableBaseByName("notepad", EPROCImageFileNameOffset, eprocActiveProcessLinks, kprocDirectoryTableBase);
		PEPROCESS pTargetEProcess = GetProcessByName("notepad", EPROCImageFileNameOffset, eprocActiveProcessLinks);
		DbgPrint("[+] pTargetEProcess at: 0x%llx | targetCR3 at: 0x%llx\n", pTargetEProcess, targetCR3);
		DWORD PEB = GetSymOffset("PEB");
		DWORD PEBLdr = GetSymOffset("PEBLdr");
		DWORD LdrListHead = GetSymOffset("LdrListHead");
		DWORD LdrListEntry = GetSymOffset("LdrListEntry");
		DWORD LdrBaseDllName = GetSymOffset("LdrBaseDllName");
		DWORD LdrBaseDllBase = GetSymOffset("LdrBaseDllBase");
		DbgPrint("[+] PEB at: 0x%lx | PEBLdr at: 0x%lx | LdrListHead at: 0x%lx | LdrListEntry at: 0x%lx | LdrBaseDllName at: 0x%lx\n",
			PEB, PEBLdr, LdrListHead, LdrListEntry, LdrBaseDllName);
		DWORD TargetVAOffset = GetSymOffset("TargetVA");
		WCHAR TargetName = L"ntmarta.dll";
		// Actually now the base address
		// Instead of this we retrieve the base address from VAD-Tree -> StartingVPN * 0x1000
		// We can get the base-address my attaching to the process and then .reload /user and then ? notepad
		//unsigned long long TargetVAMarta = WalkLoadedModulesInTargetProcess(pTargetEProcess, &TargetName, PEB, PEBLdr, LdrListHead, LdrListEntry, LdrBaseDllName, LdrBaseDllBase);
		unsigned long long TargetVAMarta = 0x0;

		WalkVAD(pTargetEProcess, VADRootOffset, StartingVpnOffset, EndingVpnOffset,
			Left, Right, MMVADSubsectionOffset, MMVADControlAreaOffset, MMVADCAFilePointerOffset,
			FILEOBJECTFileNameOffset, TargetVAMarta);
		TargetVAMarta = RandAddr;
		if (TargetVAMarta == 0x0) {
			DbgPrint("[-] Could not find target process\n");
			return STATUS_SUCCESS;
		}
		DbgPrint("[+] StealingFromBase: 0x%llx\n", TargetVAMarta);

		if (sourceCR3 == 0x0 || pSourceEProcess == NULL || targetCR3 == 0x0 || pTargetEProcess == NULL) {
			DbgPrint("[-] Could not find source or target process\n");
			return STATUS_SUCCESS;
		}

		unsigned long long result = ((unsigned long long)RandAddr << 16) | TargetVAOffset;
		int cpuInfo[4] = { 0 };
		__cpuid(cpuInfo, 0x80000008);  // Get address width info
		int physicalAddressBits = cpuInfo[0] & 0xFF;  // Bits 7:0 contain PA width
		DbgPrint("Current M (Maximum Physical Address Width): %d\n", physicalAddressBits);

		WalkVAD(pSourceEProcess, VADRootOffset, StartingVpnOffset, EndingVpnOffset,
			Left, Right, MMVADSubsectionOffset, MMVADControlAreaOffset, MMVADCAFilePointerOffset,
			FILEOBJECTFileNameOffset, sourceVA);
		VirtToPhys(sourceVA, pSourceEProcess, sourceCR3, TRUE);
		globalSourceProcess = pSourceEProcess;
		ChangeRef(sourceVA, pSourceEProcess, sourceCR3, TargetVAMarta, pTargetEProcess, targetCR3);
		//BOOLEAN TLBClear = KeInvalidateAllCaches();
		//DbgPrint("[+] TLB cleared: %d\n", TLBClear);

		// Restore all modified PTEs back to their original values
		// The TRUE parameter indicates that you want to flush the entire TLB after restoration
		//status = RestoreModifiedPTEs(TRUE);
		status = STATUS_SUCCESS;
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

	if (OrigVal != 0x0 && OrigPhys.QuadPart != 0x0 && globalSourceProcess != NULL) {
		PKAPC_STATE ApcState;
		KeStackAttachProcess(globalSourceProcess, &ApcState);
		PVOID* temp = MmGetVirtualForPhysical(OrigPhys);
		memcpy(temp, &OrigVal, sizeof(OrigVal));
		unsigned long long curVal = *temp;
		if (curVal != 0x0) {
			if (curVal == OrigVal) {
				DbgPrint("[+] Successfully restored all modified PTEs to their original values\n");
			}
			else {
				DbgPrint("[-] Failed to restore modified PTEs\n");
			}
		}
		else {
			DbgPrint("[-] MmGetVirtualForPhysical has no content\n");
		}
		KeUnstackDetachProcess(&ApcState);
	}
	else {
		DbgPrint("[-] No modified PTEs to restore\n");
	}

	if (SymbolList != NULL)
		ExFreePool(SymbolList);

	IoDeleteSymbolicLink(&usSymbolicLinkName);
	IoDeleteDevice(gpDeviceObject);
	return;
}
