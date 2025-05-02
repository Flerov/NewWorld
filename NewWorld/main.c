#include <ntifs.h>
#include "main.h"


#define MAPPING_NAME_INPUT  L"\\BaseNamedObjects\\MySharedMemory"
#define MAPPING_NAME_OUTPUT L"\\BaseNamedObjects\\VADSharedMemory"
#define MAPPING_NAME_FROM_FILENAMES L"\\BaseNamedObjects\\VADSharedMemoryFileNames"
#define MAPPING_NOTIFICATION_LINK_EVENT L"\\BaseNamedObjects\\Global\\LinkMemory"
#define MAPPING_NOTIFICATION_Unlink_EVENT L"\\BaseNamedObjects\\Global\\UnlinkMemory"
#define MAPPING_NOTIFICATION_INIT_EVENT L"\\BaseNamedObjects\\Global\\InitializeMemory"
#define MAPPING_NOTIFICATION_USERMODEREADY_EVENT L"\\BaseNamedObjects\\Global\\UserModeReadEvent"
PRESET_UNICODE_STRING(usDeviceName, CSTRING(DRV_DEVICE));
PRESET_UNICODE_STRING(usSymbolicLinkName, CSTRING(DRV_LINK));

PDEVICE_OBJECT gpDeviceObject = NULL;
PDEVICE_CONTEXT gpDeviceContext = NULL;
PEPROCESS gSourceProcess = NULL;
PHYSICAL_ADDRESS gOrigPhys = { 0 };
unsigned long long gOrigVal = 0x0;
// =================================================================
// GLOBAL VARIABLES
// =================================================================
SIZE_T   gViewSize = 0;
SIZE_T   gFileNameViewSize = 0;
SIZE_T	 gCurrFileNameOffset = 1;
SIZE_T   gSecVADIndex = 0;
PVOID    gSection = 0;
PVOID    gFileNameSection = 0;
SIZE_T   gSymsViewSize = 0;
//PVOID    gSymbolList = 0;
INIT     gInit = { 0 };
SYM_INFO gSymInfo = { 0 };
HANDLE hInSection;
PVOID pInSection = NULL;

HANDLE hEventLINK;
HANDLE hEventUnlink;
HANDLE hEventUSERMODEREADY;
HANDLE hEventINIT;


NTSTATUS DriverInitialize(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pusRegistryPath) {
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS status = STATUS_DEVICE_CONFIGURATION_ERROR;

	if ((status = IoCreateDevice(
		pDriverObject, DEVICE_CONTEXT_,
		&usDeviceName, FILE_DEVICE_NW_INTERFACE,
		0, FALSE, &pDeviceObject)) == STATUS_SUCCESS) {
		// ---
		gpDeviceObject = pDeviceObject;
		gpDeviceContext = pDeviceObject->DeviceExtension;

		gpDeviceContext->pDriverObject = pDriverObject;
		gpDeviceContext->pDeviceObject = pDeviceObject;
	}
	else {
		DbgPrint("[-] Failed to create device object: %08X\n", status);
		return status;
	}
	DbgPrint("[+] Device object created: %d\n", status);
	return status;
}

void DriverUnload(PDRIVER_OBJECT pDriverObject) {
	//if (gSymbolList != NULL)
	//	ExFreePool(gSymbolList);
	
	ZwClose(hEventLINK);
	ZwClose(hEventUnlink);
	ZwClose(hEventINIT);
	ZwClose(hEventUSERMODEREADY);

	ZwUnmapViewOfSection(ZwCurrentProcess(), hInSection);
	ZwClose(hInSection);

	DbgPrint("[+] Freeing space...\n");
	ZwUnmapViewOfSection(ZwCurrentProcess(), gpDeviceContext->hSection);
	ZwClose(gpDeviceContext->hSection);

	DbgPrint("[+] Freeing space for FileName...\n");
	ZwUnmapViewOfSection(ZwCurrentProcess(), gpDeviceContext->hSectionFileName);
	ZwClose(gpDeviceContext->hSectionFileName);

	DbgPrint("[+] Unloading driver...\n");
	//ObDereferenceObject(hEventUSERMODEREADY);
	//ObDereferenceObject(hEventUnlink);
	//ObDereferenceObject(hEventLINK);
	IoDeleteSymbolicLink(&usSymbolicLinkName);
	IoDeleteDevice(gpDeviceObject);
	return;
}
// -----------------------------------------------------------------
BOOL InitData() {
	if (pInSection == NULL)
		return FALSE;

	PINIT initPos = (PINIT)pInSection;

	// Compare as 4 separate characters or use a proper string comparison
	if (initPos->identifier[0] == 'I' &&
		initPos->identifier[1] == 'N' &&
		initPos->identifier[2] == 'I' &&
		initPos->identifier[3] == 'T') {

		gInit = *initPos;
		return TRUE;
	}

	return FALSE;
}
// -----------------------------------------------------------------
UINT64 GetSymOffset(const char* str) {
	if (pInSection == NULL)
		return 0;

	// Calculate the address after the INIT structure
	PSYMBOL syms = (PSYMBOL)((PINIT)pInSection + sizeof(INIT));

	// Calculate maximum symbols based on remaining size
	size_t maxSymCount = (gSymsViewSize - sizeof(INIT)) / sizeof(SYMBOL);

	for (size_t i = 0; i < maxSymCount; i++) {
		if (strcmp(syms[i].name, str) == 0) {
			return syms[i].offset;
		}
	}

	return 0;
}
// -----------------------------------------------------------------
BOOL InitSymInfo() {
	gSymInfo.EProcUniqueProcessId = GetSymOffset("eprocUniqueProcessId");
	gSymInfo.EProcActiveProcessLinks = GetSymOffset("eprocActiveProcessLinks");
	gSymInfo.KPROCDirectoryTableBase = GetSymOffset("kprocDirectoryTableBase");
	//gSymInfo.sourceVA = GetSymOffset("sourceVA");
	//gSymInfo.targetVPN = GetSymOffset("targetVPN");
	gSymInfo.VADRoot = GetSymOffset("VADRoot");
	gSymInfo.StartingVpnOffset = GetSymOffset("StartingVpn");
	gSymInfo.EndingVpnOffset = GetSymOffset("EndingVpn");
	gSymInfo.Left = GetSymOffset("Left");
	gSymInfo.Right = GetSymOffset("Right");
	gSymInfo.MMVADSubsection = GetSymOffset("MMVADSubsection");
	gSymInfo.MMVADControlArea = GetSymOffset("MMVADControlArea");
	gSymInfo.MMVADCAFilePointer = GetSymOffset("MMVADCAFilePointer");
	gSymInfo.FILEOBJECTFileName = GetSymOffset("FILEOBJECTFileName");
	gSymInfo.EProcImageFileName = GetSymOffset("EPROCImageFileName");
	gSymInfo.PEB = GetSymOffset("PEB");
	gSymInfo.PEBLdr = GetSymOffset("PEBLdr");
	gSymInfo.LdrListHead = GetSymOffset("LdrListHead");
	gSymInfo.LdrListEntry = GetSymOffset("LdrListEntry");
	gSymInfo.LdrBaseDllName = GetSymOffset("LdrBaseDllName");
	gSymInfo.LdrBaseDllBase = GetSymOffset("LdrBaseDllBase");
	return TRUE;
}
// -----------------------------------------------------------------
BOOL InsertVADNode(int Level,
	PVOID VADNode,
	unsigned long long StartingVpn,
	unsigned long long EndingVpn,
	UNICODE_STRING* FileName) {

	if (gViewSize / sizeof(VAD_NODE) <= gSecVADIndex) {
		DbgPrint("[-] VAD node index out of bounds\n");
		return FALSE;
	}
	if (gFileNameViewSize / sizeof(VAD_NODE_FILE) <= gCurrFileNameOffset) {
		return FALSE;
	}

	PVAD_NODE CurrVADNode = (PVAD_NODE)gSection;
	PVAD_NODE_FILE FileNameBuffer = (PVAD_NODE_FILE)gFileNameSection;
	
	CurrVADNode[gSecVADIndex].Level = Level;
	CurrVADNode[gSecVADIndex].VADNode = VADNode;
	CurrVADNode[gSecVADIndex].StartingVpn = StartingVpn;
	CurrVADNode[gSecVADIndex].EndingVpn = EndingVpn;
	CurrVADNode[gSecVADIndex].FileOffset = 0;
	if (FileName != NULL && FileName->Length > 0 && FileName->Length < gViewSize) {
		ANSI_STRING test;
		if (NT_SUCCESS(RtlUnicodeStringToAnsiString(
			&test,
			FileName,
			TRUE))) {
			size_t size = min(test.Length, sizeof(VAD_NODE_FILE));
			memcpy(FileNameBuffer[gCurrFileNameOffset].FileName, test.Buffer, size);
			FileNameBuffer[gCurrFileNameOffset].FileName[min(size, MAX_FILENAME_SIZE - 1)] = '\0';
			CurrVADNode[gSecVADIndex].FileOffset = gCurrFileNameOffset;
			RtlFreeAnsiString(&test);
			gCurrFileNameOffset++;
		} else {
			DbgPrint("[-] Failed to convert FileName to ANSI\n");
		}
	}

	gSecVADIndex++;
	return TRUE;
}
// -----------------------------------------------------------------
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
// -----------------------------------------------------------------
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

	UNICODE_STRING* FileName = GetFileObjectFromVADLeaf(VADNode, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName);

	// Print current node with fixed width formatting
	// Add indicator if this range contains the target address
	//if (FileName == NULL) {
	//	DbgPrint("%-10d 0x%p          0x%010I64x     0x%010I64x\n",
	//		Level,
	//		VADNode,
	//		StartingVpn,
	//		EndingVpn);
	//}
	//else {
	//	DbgPrint("%-10d 0x%p          0x%010I64x     0x%010I64x     %wZ\n",
	//		Level,
	//		VADNode,
	//		StartingVpn,
	//		EndingVpn,
	//		FileName);
	//}
	InsertVADNode(Level, VADNode, StartingVpn, EndingVpn, FileName);

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
// -----------------------------------------------------------------
VOID WalkVAD(  PEPROCESS TargetProcess,
						  DWORD VADRootOffset,
						  DWORD StartingVpnOffset,
						  DWORD EndingVpnOffset,
						  DWORD Left,
						  DWORD Right,
						  DWORD MMVADSubsection,
						  DWORD MMVADControlArea,
						  DWORD MMVADCAFilePointer,
						  DWORD FILEOBJECTFileName,
						  unsigned long long targetAdr  ) {

	PVOID* pVADRoot = (PVOID*)((ULONG_PTR)TargetProcess + VADRootOffset);
	if (!MmIsAddressValid(*pVADRoot)) {
		DbgPrint("[-] VAD tree is empty | *pVADRoot: 0x%llx -> TargetProcess: 0x%llx + VADRootOffset: 0x%lx\n", *pVADRoot, TargetProcess, VADRootOffset);
		return;
	}

	// Print header with consistent column widths
	//DbgPrint("\nLevel      VADNode                StartingVpn        EndingVpn          FileName\n");
	//DbgPrint("-----      -------                -----------        ---------          --------\n");

	// Variables to track statistics
	ULONG totalVADs = 0;
	ULONG totalLevels = 0;
	ULONG maxDepth = 0;
	gSecVADIndex = 0;

	// Call recursive function with statistics tracking - passing the targetAdr
	WalkVADRecursive(*pVADRoot, StartingVpnOffset, EndingVpnOffset, Left, Right, 1,
		&totalVADs, &totalLevels, &maxDepth, MMVADSubsection, MMVADControlArea, MMVADCAFilePointer, FILEOBJECTFileName,
		targetAdr);

	// Calculate and print statistics
	//ULONG avgLevel = (totalVADs > 0) ? totalLevels / totalVADs : 0;
	//ULONG avgLevelFrac = (totalVADs > 0) ? ((totalLevels * 100) / totalVADs) % 100 : 0;
	//DbgPrint("Total VADs: %lu, average level: %lu.%02lu, maximum depth: %lu\n\n",
	//	totalVADs, avgLevel, avgLevelFrac, maxDepth);
}
// -----------------------------------------------------------------
PEPROCESS GetProcessByName(
	const char* FileName,
	unsigned long long eprocImageFileNameOffset,
	unsigned long long eprocActiveProcessLinks) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	PCHAR CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
	size_t FileNameSize = (strlen(FileName) > 15) ? 14 : strlen(FileName); // 14 cause of null terminator
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
// -----------------------------------------------------------------
unsigned long long GetDirectoryTableBaseByName(
	const char* FileName,
	unsigned long long eprocImageFileNameOffset,
	unsigned long long eprocActiveProcessLinks,
	unsigned long long kprocDirectoryTableBase) {
	PVOID CurrEProc = PsGetCurrentProcess();
	PVOID StartProc = CurrEProc;
	PLIST_ENTRY CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	PCHAR CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
	size_t FileNameSize = (strlen(FileName) > 14) ? 14 : strlen(FileName);
	do {
		//DbgPrint("[*] GetDirectoryTableBaseByName: CurrentProcess: 0x%llx | FileName: %s\n", CurrEProc, CurrentImageName);
		if (!MmIsAddressValid(CurrEProc)) {
			DbgPrint("[-] Invalid EPROCESS address: 0x%llx\n", CurrEProc);
			return 0x0;
		}
		if (memcmp(FileName, CurrentImageName, FileNameSize) == 0) {
			PVOID* test = (unsigned long long)CurrEProc + kprocDirectoryTableBase;
			//DbgPrint("[*] GetDirectoryTableBaseByName: Found Process: 0x%llx | DirectoryTableBase: 0x%llx\n", CurrEProc, *test);
			return *test;
		}
		CurrEProc = (ULONG_PTR)CurList->Flink - eprocActiveProcessLinks;
		CurrentImageName = (PCHAR)((ULONG_PTR)CurrEProc + eprocImageFileNameOffset);
		CurList = (PLIST_ENTRY)((ULONG_PTR)CurrEProc + eprocActiveProcessLinks);
	} while ((ULONG_PTR)StartProc != (ULONG_PTR)CurrEProc);
	return 0x0;
}
// -----------------------------------------------------------------
VOID ChangeRef(
	unsigned long long SourceVA, PEPROCESS SourceProcess, unsigned long long SourceCR3,
	unsigned long long TargetVA, PEPROCESS TargetProcess, unsigned long long TargetCR3) {
	if (SourceVA == 0x0 || TargetVA == 0x0) {
		DbgPrint("[-] ChangeRef: SourceVA or TargetVA is NULL\n");
		return;
	}
	DbgPrint("[*] ChangeRef: SourceVA: 0x%llx | SourceProcess: 0x%llx | SourceCR3: 0x%llx\n", SourceVA, SourceProcess, SourceCR3);
	DbgPrint("[*] ChangeRef: TargetVA: 0x%llx | TargetProcess: 0x%llx | TargetCR3: 0x%llx\n", TargetVA, TargetProcess, TargetCR3);

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
	MDL* pMdlTarget = IoAllocateMdl(TargetVA, 4096, FALSE, FALSE, NULL);
	MmProbeAndLockPages(pMdlTarget, UserMode, IoReadAccess);

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
		if (PDERaw->PageSize == 0) {
			// 1 = Maps a 2 MB page, 0 = Points to a page table.
			PhysPage.PhysicalAddress.QuadPart = (pde & 0xFFFFF000) + (PTOffset * 0x08);
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&pte, PhysPage, sizeof(pte), MM_COPY_MEMORY_PHYSICAL, &numRec);
			TargetPFN = pte;
			DbgPrint("Got PT-Base: 0x%llx\n", TargetPFN);
			pte = pte & 0xFFFFFFFFFFFF; // Mask out the upper bits
			DbgPrint("Target PTE: 0x%llx\n", pte);
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
	MmUnlockPages(pMdlTarget);
	IoFreeMdl(pMdlTarget);
	KeUnstackDetachProcess(&ApcState);

	// Source Process
	DbgPrint("Get for Source\n");
	KeStackAttachProcess(SourceProcess, &ApcState);
	MDL* pMdlSource = IoAllocateMdl(SourceVA, 4096, FALSE, FALSE, NULL);
	MmProbeAndLockPages(pMdlSource, UserMode, IoReadAccess);

	PML4Offset = (SourceVA & 0xFF8000000000) >> 0x27; // Page Map Level 4 Offset
	PDPTOffset = (SourceVA & 0x7FC0000000) >> 0x1E;   // Page Directory Pointer Table Offset
	PDOffset = (SourceVA & 0x3FE00000) >> 0x15;       // Page Directory Offset
	PTOffset = (SourceVA & 0x1FF000) >> 0x0C;         // Page Table Offset
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
			Phys.PhysicalAddress.QuadPart = PhysPage.PhysicalAddress.QuadPart + MaskOffset;
			status = MmCopyMemory(&physAdr, Phys, sizeof(physAdr), MM_COPY_MEMORY_PHYSICAL, &numRec);
			gOrigPhys.QuadPart = Phys.PhysicalAddress.QuadPart;
			gOrigVal = physAdr;
			physAdr = physAdr & 0xFFFFFFFFFFFF; // Mask out the upper bits
			DbgPrint("Source PTE: 0x%llx\n", physAdr);
			PTERaw = (PTE*)&physAdr;
			PHYSRaw4KB = (PHYSICAL_4KB*)&physAdr;
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
		memcpy(temp, &TargetPFN, sizeof(TargetPFN)); // the size should be correct
		DbgPrint("CHANGED\n");
		__invlpg(SourceVA);
		MmUnlockPages(pMdlSource);
		IoFreeMdl(pMdlSource);
		KeUnstackDetachProcess(&ApcState);
		return;
	}
	else {
		DbgPrint("[-] PTERaw is NULL\n");
		MmUnlockPages(pMdlSource);
		IoFreeMdl(pMdlSource);
		KeUnstackDetachProcess(&ApcState);
	}
	DbgPrint("Returning\n");
	return;
}
// -----------------------------------------------------------------
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
	PDE* PDERaw = 0x0; // Page Directory Entry
	PTE* PTERaw = 0x0; // Page Table Entry
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
			}
			else {
				DbgPrint("[+] PHYS 2MB-\n"
					"\t[*] Offset: %llx\n"
					"\t[*] PageNumber: %llx\n"
					"\t[*] Value: %llx\n",
					PHYSRaw2MB->Offset, PHYSRaw2MB->PageNumber, PHYSRaw2MB->Value);
			}
		}
		else {
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
// -----------------------------------------------------------------
BOOL g_StopRequested = FALSE;
VOID WorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Event signaled\n");
		}
		else {
			DbgPrint("[-] WorkerThread Failed to wait for event: %08X\n", status);
		}
		g_StopRequested = TRUE;
		pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID LinkWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] LinkWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		gSourceProcess = GetProcessByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		unsigned long long targetCR3 = GetDirectoryTableBaseByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		unsigned long long sourceCR3 = GetDirectoryTableBaseByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks, gSymInfo.KPROCDirectoryTableBase);
		if (gInit.targetVPN != 0x0) {
			PVOID targetVA = gInit.targetVPN * 0x1000;
			VirtToPhys(gInit.sourceVA, gSourceProcess, sourceCR3, TRUE);
			//VirtToPhys(targetVA, pTargetProcess, targetCR3, TRUE);
			ChangeRef(gInit.sourceVA, gSourceProcess, sourceCR3, targetVA, pTargetProcess, targetCR3);
		}
		pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UnlinkWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UnlinkWorkerThread, Failed to wait for event: %08X\n", status);
			break;
		}
		if (gOrigVal != 0x0 && gOrigPhys.QuadPart != 0x0 && gSourceProcess != NULL) {
			PKAPC_STATE ApcState;
			DbgPrint("gSourceProcess: 0x%llx\n", gSourceProcess);
			KeStackAttachProcess(gSourceProcess, &ApcState);
			PVOID* temp = MmGetVirtualForPhysical(gOrigPhys);
			memcpy(temp, &gOrigVal, sizeof(gOrigVal));
			unsigned long long curVal = *temp;
			if (curVal != 0x0) {
				if (curVal == gOrigVal) {
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
		pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID UserModeReadWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL); // TODO: perhaps change to WaitForMultipleObjects
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		// Make sure section is not getting paged-out | VAD Node Info - Memory Section
		DbgPrint("[+] Allocating MDL for section\n");
		gpDeviceContext->pMdl = IoAllocateMdl(gSection, gViewSize, FALSE, FALSE, NULL);
		DbgPrint("[+] Probing and locking pages\n");
		MmProbeAndLockPages(gpDeviceContext->pMdl, KernelMode, IoReadAccess);
		// Make sure section is not getting paged-out | VAD Node FileName Info - Memory Section
		DbgPrint("[+] Allocating MDL for section for FileName\n");
		gpDeviceContext->pFileNameMdl = IoAllocateMdl(gFileNameSection, gFileNameViewSize, FALSE, FALSE, NULL);
		DbgPrint("[+] Probing and locking pages for FileName\n");
		MmProbeAndLockPages(gpDeviceContext->pFileNameMdl, KernelMode, IoReadAccess);

		DbgPrint("[+] Source Process: %s\n", gInit.sourceProcess);
		DbgPrint("[+] Target Process: %s\n", gInit.targetProcess);
		gSourceProcess = GetProcessByName(gInit.sourceProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);
		PEPROCESS pTargetProcess = GetProcessByName(gInit.targetProcess, gSymInfo.EProcImageFileName, gSymInfo.EProcActiveProcessLinks);

		RtlZeroMemory(gFileNameSection, gFileNameViewSize);
		if (pTargetProcess != NULL) {
			WalkVAD(pTargetProcess, gSymInfo.VADRoot, gSymInfo.StartingVpnOffset, gSymInfo.EndingVpnOffset,
				gSymInfo.Left, gSymInfo.Right, gSymInfo.MMVADSubsection, gSymInfo.MMVADControlArea,
				gSymInfo.MMVADCAFilePointer, gSymInfo.FILEOBJECTFileName, 0x0);
		}

		MmUnlockPages(gpDeviceContext->pMdl);
		IoFreeMdl(gpDeviceContext->pMdl);

		MmUnlockPages(gpDeviceContext->pFileNameMdl);
		IoFreeMdl(gpDeviceContext->pFileNameMdl);
		pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
VOID INITWorkerThread(PVOID Context) {
	PKEVENT pEvent = (PKEVENT)Context;
	int test;
	while (!g_StopRequested) {
		NTSTATUS status = KeWaitForSingleObject(pEvent, Executive, KernelMode, FALSE, NULL); // TODO: perhaps change to WaitForMultipleObjects
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] UserModeReadWorkerThread Failed to wait for event: %08X\n", status);
			break;
		}
		if (pInSection == NULL) {
			//RtlZeroMemory(pInSection, gSymsViewSize);
			status = ZwMapViewOfSection(hInSection, ZwCurrentProcess(), &pInSection,
				0, 0, NULL, &gSymsViewSize, ViewShare,
				0, PAGE_READONLY);
			if (!NT_SUCCESS(status)) {
				DbgPrint("[-] Failed to map view of input section: %08X\n", status);
				ZwClose(hInSection);
				IoDeleteSymbolicLink(&usSymbolicLinkName);
				IoDeleteDevice(gpDeviceObject);
				return status;
			}
			DbgPrint("[+] Initializing Sym Info\n");
			if (!InitSymInfo()) {
				DbgPrint("[-] Failed to initialize symbol information\n");
				//ExFreePool(gSymbolList);
				//IoDeleteSymbolicLink(&usSymbolicLinkName);
				//IoDeleteDevice(gpDeviceObject);
				return STATUS_UNSUCCESSFUL;
			}
		}
		DbgPrint("[+] Initializing INIT Data %llx\n", status);
		if (!InitData()) {
			DbgPrint("[-] Failed to initialize data\n");
			//ExFreePool(gSymbolList);
			//IoDeleteSymbolicLink(&usSymbolicLinkName);
			//IoDeleteDevice(gpDeviceObject);
			return STATUS_UNSUCCESSFUL;
		}
		DbgPrint("[+] Finished initializing data and symbol information\n");
		pEvent->Header.SignalState = 0; // Reset the event


		//// Make sure section is not getting paged-out
		//MDL* pInMdl = IoAllocateMdl(pInSection, gSymsViewSize, FALSE, FALSE, NULL);
		//MmProbeAndLockPages(pInMdl, KernelMode, IoReadAccess);
		//
		//// Allocate enough space for INPUT section' content
		//gSymbolList = ExAllocatePool(NonPagedPool, gSymsViewSize);
		//if (!(gSymbolList == NULL)) {
		//	memcpy(gSymbolList, pInSection, gSymsViewSize);
		//	DbgPrint("[*] Section size: %zu Bytes | Section Base: 0x%llx | SymbolList Base: 0x%llx\n",
		//		gSymsViewSize, pInSection, gSymbolList);
		//}
		//else {
		//	DbgPrint("[-] Failed to allocate memory for input section: %llx\n", status);
		//	MmUnlockPages(pInMdl);
		//	IoFreeMdl(pInMdl);
		//	ZwUnmapViewOfSection(ZwCurrentProcess(), hInSection);
		//	ZwClose(hInSection);
		//	IoDeleteSymbolicLink(&usSymbolicLinkName);
		//	IoDeleteDevice(gpDeviceObject);
		//	return status;
		//}
		//DbgPrint("[+] Input section mapped successfully: %llx\n", status);
		//MmUnlockPages(pInMdl);
		//IoFreeMdl(pInMdl);
		////ZwUnmapViewOfSection(ZwCurrentProcess(), hInSection);
		////ZwClose(hInSection);
		//
		//DbgPrint("[+] Initializing INIT Data %llx\n", status);
		//if (!InitData()) {
		//	DbgPrint("[-] Failed to initialize data\n");
		//	ExFreePool(gSymbolList);
		//	IoDeleteSymbolicLink(&usSymbolicLinkName);
		//	IoDeleteDevice(gpDeviceObject);
		//	return STATUS_UNSUCCESSFUL;
		//}
		//DbgPrint("[+] Initializing Sym Info\n");
		//if (!InitSymInfo()) {
		//	DbgPrint("[-] Failed to initialize symbol information\n");
		//	ExFreePool(gSymbolList);
		//	IoDeleteSymbolicLink(&usSymbolicLinkName);
		//	IoDeleteDevice(gpDeviceObject);
		//	return STATUS_UNSUCCESSFUL;
		//}
		//DbgPrint("[+] Finished initializing data and symbol information\n");
		//pEvent->Header.SignalState = 0; // Reset the event
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
NTSTATUS DriverEntry(  PDRIVER_OBJECT pDriverObject,
					   PUNICODE_STRING pusRegistryPath  ) {

	NTSTATUS status = STATUS_DEVICE_CONFIGURATION_ERROR;

	if ((status = DriverInitialize(pDriverObject, pusRegistryPath)) == STATUS_SUCCESS) {
		pDriverObject->DriverUnload = DriverUnload;
		gpDeviceContext->gSectionMapped = FALSE;

		// START - Section for Input
		OBJECT_ATTRIBUTES InAttr;
		UNICODE_STRING InSectionName;
		PVOID InSectionObject = NULL;
		LARGE_INTEGER InSecSize;
		InSecSize.QuadPart = 0x2000;

		SECURITY_DESCRIPTOR sdInSecurityDescriptor;
		ACL sdInAcl;
		RtlCreateSecurityDescriptor(&sdInSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
		RtlSetDaclSecurityDescriptor(&sdInSecurityDescriptor, TRUE, NULL, FALSE);
		RtlInitUnicodeString(&InSectionName, MAPPING_NAME_INPUT);
		InitializeObjectAttributes(&InAttr, &InSectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdInSecurityDescriptor);
		
		//status = ZwOpenSection(&hInSection, SECTION_MAP_READ, &InAttr); // TODO: I think this can stay User-Mode
		status = ZwCreateSection(&hInSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&InAttr, &InSecSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // why can we not specify maximum sizeLow but only maximum sizeHigh????
		// Restarting the user-mode application our buffer will still be buffered
		// But this requires the kernel driver to start after the SYMBOLS habe been writte to the
		// section. Otherwise the driver will not be able to read the symbols.
		if (!NT_SUCCESS(status) || hInSection == NULL) {
			DbgPrint("[-] Failed to create input section: %08X\n", status);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gSymsViewSize = 0;
		LARGE_INTEGER InSectionOffset = { 0 };

		// END - Section for Input
		// -----------------------------------------------------------------
		// Section for Info from Driver
		// START - Section for Output
		OBJECT_ATTRIBUTES attr;
		UNICODE_STRING sectionName;
		PVOID sectionObject = NULL;
		LARGE_INTEGER sectionSize;
		sectionSize.QuadPart = 0x3000; // or whatever size you want, 4KB in this case
		SECURITY_DESCRIPTOR sdSecurityDescriptor;
		ACL sdAcl;
		RtlCreateSecurityDescriptor(&sdSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
		RtlSetDaclSecurityDescriptor(&sdSecurityDescriptor, TRUE, NULL, FALSE);

		DbgPrint("[+] Initializing Section Name\n");
		RtlInitUnicodeString(&sectionName, MAPPING_NAME_OUTPUT);
		InitializeObjectAttributes(&attr, &sectionName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);

		DbgPrint("[+] Creating section for output\n");
		//status = ZwOpenSection(&gpDeviceContext->hSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE, &attr);
		status = ZwCreateSection(&gpDeviceContext->hSection, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&attr, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // why can we not specify maximum sizeLow but only maximum sizeHigh????
		if (!NT_SUCCESS(status) || gpDeviceContext->hSection == NULL) {
			DbgPrint("[-] Failed to open section: %llx\n", status);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gViewSize = 0;
		LARGE_INTEGER SectionOffset = { 0 };

		DbgPrint("[+] Mapping view of section\n");
		status = ZwMapViewOfSection(gpDeviceContext->hSection, ZwCurrentProcess(), &gSection,
			0, 0, NULL, &gViewSize, ViewShare,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] Failed to map view of section: %llx\n", status);
			ZwClose(gpDeviceContext->hSection);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		DbgPrint("[+] Section size: %zu Bytes | Section Base: 0x%llx\n",
			gViewSize, gSection);

		// Make sure section is not getting paged-out
		//DbgPrint("[+] Allocating MDL for section\n");
		//gpDeviceContext->pMdl = IoAllocateMdl(gSection, gViewSize, FALSE, FALSE, NULL);
		//DbgPrint("[+] Probing and locking pages\n");
		//MmProbeAndLockPages(gpDeviceContext->pMdl, KernelMode, IoReadAccess);

		gpDeviceContext->gSectionMapped = TRUE;
		// -----------------------------------------------------------------
		// Section for FileName-Info from Driver
		OBJECT_ATTRIBUTES attrFileName;
		UNICODE_STRING sectionFileName;
		PVOID sectionFileNameObject = NULL;
		LARGE_INTEGER sectionSizeFILENAMES;
		sectionSizeFILENAMES.QuadPart = 0x2000; // or whatever size you want, 4KB in this case

		DbgPrint("[+] Initializing Section Name for FileName\n");
		RtlInitUnicodeString(&sectionFileName, MAPPING_NAME_FROM_FILENAMES);
		InitializeObjectAttributes(&attrFileName, &sectionFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);

		//status = ZwOpenSection(&gpDeviceContext->hSectionFileName, SECTION_ALL_ACCESS | SECTION_MAP_WRITE, &attrFileName);
		status = ZwCreateSection(&gpDeviceContext->hSectionFileName, SECTION_ALL_ACCESS | SECTION_MAP_WRITE,
			&attrFileName, &sectionSizeFILENAMES, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // why can we not specify maximum sizeLow but only maximum sizeHigh????
		if (!NT_SUCCESS(status) || gpDeviceContext->hSectionFileName == NULL) {
			DbgPrint("[-] Failed to open section for FileName: %llx\n", status);
			ZwClose(gpDeviceContext->hSection);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}

		gFileNameViewSize = 0;
		LARGE_INTEGER SectionFileNameOffset = { 0 };

		DbgPrint("[+] Mapping view of section for FileName\n");
		status = ZwMapViewOfSection(gpDeviceContext->hSectionFileName, ZwCurrentProcess(), &gFileNameSection,
			0, 0, NULL, &gFileNameViewSize, ViewUnmap,
			0, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			DbgPrint("[-] Failed to map view of section for FileName: %llx\n", status);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		DbgPrint("[+] Section size for FileName: %zu Bytes | Section Base: 0x%llx\n",
			gFileNameViewSize, gFileNameSection);

		// Make sure section is not getting paged-out
		//DbgPrint("[+] Allocating MDL for section for FileName\n");
		//gpDeviceContext->pFileNameMdl = IoAllocateMdl(gFileNameSection, gFileNameViewSize, FALSE, FALSE, NULL);
		//DbgPrint("[+] Probing and locking pages for FileName\n");
		//MmProbeAndLockPages(gpDeviceContext->pFileNameMdl, KernelMode, IoReadAccess);

		gpDeviceContext->gFileNameSectionMapped = TRUE;
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_USERMODEREADY_EVENT START
		UNICODE_STRING eventNameUSERMODEREADY;
		OBJECT_ATTRIBUTES objAttrUSERMODEREADY;
		HANDLE hThreadUSERMODEREADY;
		PKEVENT pEventUSERMODEREADY;
		RtlInitUnicodeString(&eventNameUSERMODEREADY, MAPPING_NOTIFICATION_USERMODEREADY_EVENT);
		InitializeObjectAttributes(&objAttrUSERMODEREADY, &eventNameUSERMODEREADY, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		//status = ZwOpenEvent(&hEventUSERMODEREADY, EVENT_ALL_ACCESS, &objAttrUSERMODEREADY);
		status = ZwCreateEvent(&hEventUSERMODEREADY, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrUSERMODEREADY, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventUSERMODEREADY);
			ObReferenceObjectByHandle(hEventUSERMODEREADY, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventUSERMODEREADY, NULL);
			PsCreateSystemThread(&hThreadUSERMODEREADY, THREAD_ALL_ACCESS, NULL, NULL, NULL, UserModeReadWorkerThread, pEventUSERMODEREADY);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_USERMODEREADY_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_Unlink_EVENT START
		UNICODE_STRING eventNameUnlink;
		OBJECT_ATTRIBUTES objAttrUnlink;
		HANDLE hThreadUnlink;
		PKEVENT pEventUnlink;
		RtlInitUnicodeString(&eventNameUnlink, MAPPING_NOTIFICATION_Unlink_EVENT);
		InitializeObjectAttributes(&objAttrUnlink, &eventNameUnlink, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		//status = ZwOpenEvent(&hEventUnlink, EVENT_ALL_ACCESS, &objAttrUnlink);
		status = ZwCreateEvent(&hEventUnlink, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrUnlink, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventUnlink);
			ObReferenceObjectByHandle(hEventUnlink, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventUnlink, NULL);
			PsCreateSystemThread(&hThreadUnlink, THREAD_ALL_ACCESS, NULL, NULL, NULL, UnlinkWorkerThread, pEventUnlink);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ObDereferenceObject(hEventUSERMODEREADY);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_Unlink_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_LINK_EVENT START
		UNICODE_STRING eventNameLINK;
		OBJECT_ATTRIBUTES objAttrLINK;
		HANDLE hThreadLINK;
		PKEVENT pEventLINK;
		RtlInitUnicodeString(&eventNameLINK, MAPPING_NOTIFICATION_LINK_EVENT);
		InitializeObjectAttributes(&objAttrLINK, &eventNameLINK, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		//status = ZwOpenEvent(&hEventLINK, EVENT_ALL_ACCESS, &objAttrLINK);
		status = ZwCreateEvent(&hEventLINK, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrLINK, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventLINK);
			ObReferenceObjectByHandle(hEventLINK, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventLINK, NULL);
			PsCreateSystemThread(&hThreadLINK, THREAD_ALL_ACCESS, NULL, NULL, NULL, LinkWorkerThread, pEventLINK);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ObDereferenceObject(hEventUSERMODEREADY);
			ObDereferenceObject(hEventUnlink);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName); 
			ZwClose(hEventUSERMODEREADY);
			ZwClose(hEventUnlink);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_LINK_EVENT END
		// -----------------------------------------------------------------
		// MAPPING_NOTIFICATION_INIT_EVENT START
		UNICODE_STRING eventNameINIT;
		OBJECT_ATTRIBUTES objAttrINIT;
		HANDLE hThreadINIT;
		PKEVENT pEventINIT;
		RtlInitUnicodeString(&eventNameINIT, MAPPING_NOTIFICATION_INIT_EVENT);
		InitializeObjectAttributes(&objAttrINIT, &eventNameINIT, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &sdSecurityDescriptor);
		status = ZwCreateEvent(&hEventINIT, EVENT_ALL_ACCESS | SYNCHRONIZE, &objAttrINIT, NotificationEvent, FALSE);
		if (NT_SUCCESS(status)) {
			DbgPrint("[+] Opened event handle: %llx\n", hEventINIT);
			ObReferenceObjectByHandle(hEventINIT, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEventINIT, NULL);
			PsCreateSystemThread(&hThreadINIT, THREAD_ALL_ACCESS, NULL, NULL, NULL, INITWorkerThread, pEventINIT);
		}
		else {
			DbgPrint("[-] Failed to open event handle: %08X\n", status);
			ObDereferenceObject(hEventUSERMODEREADY);
			ZwClose(gpDeviceContext->hSection);
			ZwClose(gpDeviceContext->hSectionFileName);
			ZwClose(hEventUSERMODEREADY);
			IoDeleteSymbolicLink(&usSymbolicLinkName);
			IoDeleteDevice(gpDeviceObject);
			return status;
		}
		// MAPPING_NOTIFICATION_INIT_EVENT END
		// -----------------------------------------------------------------
		status = STATUS_SUCCESS;
		return status;
		// END - Section for Output
	} else {
		DbgPrint("[-] Failed to initialize driver: %llx\n", status);
		IoDeleteSymbolicLink(&usSymbolicLinkName);
		IoDeleteDevice(gpDeviceObject);
		return status;
	}
}
