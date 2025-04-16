#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")
#include <vector>
#include <iostream>
#include <tchar.h>
#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include <chrono>


#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (PCHAR)(address) - \
                                                  (ULONG_PTR)(&((type *)0)->field)))
#define EVENT_NAME L"Global\\MySharedMemoryEvent"
#define MAPPING_NAME L"Global\\MySharedMemory"
#define MAX_SYMBOLS 2
#define SHARED_MEMORY_SIZE (MAX_SYMBOLS * sizeof(SYMBOL))

size_t totalAllocationSize;
size_t totalCopiedSize;

PVOID SymbolsArray;
static int SymbolsArrayIndex = 0;
size_t SymbolsArrayAllocationSize = 0;

typedef struct _SYMBOL {
	CHAR name[32];
	unsigned long long offset;
	LIST_ENTRY ListEntry;
} SYMBOL, * PSYMBOL;

typedef struct PE_relocation_t {
	DWORD RVA;
	WORD Type : 4;
} PE_relocation;

typedef struct PE_codeview_debug_info_t {
	DWORD signature;
	GUID guid;
	DWORD age;
	CHAR pdbName[1];
} PE_codeview_debug_info;

typedef struct PE_pointers {
	BOOL isMemoryMapped;
	BOOL isInAnotherAddressSpace;
	HANDLE hProcess;
	PVOID baseAddress;
	//headers ptrs
	IMAGE_DOS_HEADER* dosHeader;
	IMAGE_NT_HEADERS* ntHeader;
	IMAGE_OPTIONAL_HEADER* optHeader;
	IMAGE_DATA_DIRECTORY* dataDir;
	IMAGE_SECTION_HEADER* sectionHeaders;
	//export info
	IMAGE_EXPORT_DIRECTORY* exportDirectory;
	LPDWORD exportedNames;
	DWORD exportedNamesLength;
	LPDWORD exportedFunctions;
	LPWORD exportedOrdinals;
	//relocations info
	DWORD nbRelocations;
	PE_relocation* relocations;
	//debug info
	IMAGE_DEBUG_DIRECTORY* debugDirectory;
	PE_codeview_debug_info* codeviewDebugInfo;
} PE;

typedef struct symbol_ctx_t {
	LPWSTR pdb_name_w;
	DWORD64 pdb_base_addr;
	HANDLE sym_handle;
} symbol_ctx;

PBYTE ReadFullFileW(LPCWSTR fileName) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return NULL;
	}
	DWORD fileSize = GetFileSize(hFile, NULL);
	PBYTE fileContent = (PBYTE)malloc(fileSize); // cast
	DWORD bytesRead = 0;
	if (!ReadFile(hFile, fileContent, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
		free(fileContent);
		fileContent = NULL;
	}
	CloseHandle(hFile);
	return fileContent;
}

IMAGE_SECTION_HEADER* PE_sectionHeader_fromRVA(PE* pe, DWORD rva) {
	IMAGE_SECTION_HEADER* sectionHeaders = pe->sectionHeaders;
	for (DWORD sectionIndex = 0; sectionIndex < pe->ntHeader->FileHeader.NumberOfSections; sectionIndex++) {
		DWORD currSectionVA = sectionHeaders[sectionIndex].VirtualAddress;
		DWORD currSectionVSize = sectionHeaders[sectionIndex].Misc.VirtualSize;
		if (currSectionVA <= rva && rva < currSectionVA + currSectionVSize) {
			return &sectionHeaders[sectionIndex];
		}
	}
	return NULL;
}

PVOID PE_RVA_to_Addr(PE* pe, DWORD rva) {
	PVOID peBase = pe->dosHeader;
	if (pe->isMemoryMapped) {
		return (PBYTE)peBase + rva;
	}

	IMAGE_SECTION_HEADER* rvaSectionHeader = PE_sectionHeader_fromRVA(pe, rva);
	if (NULL == rvaSectionHeader) {
		return NULL;
	}
	else {
		return (PBYTE)peBase + rvaSectionHeader->PointerToRawData + (rva - rvaSectionHeader->VirtualAddress);
	}
}

PE* PE_create(PVOID imageBase, BOOL isMemoryMapped) {
	PE* pe = (PE*)calloc(1, sizeof(PE));
	if (NULL == pe) {
		exit(1);
	}
	pe->isMemoryMapped = isMemoryMapped;
	pe->isInAnotherAddressSpace = FALSE;
	pe->hProcess = INVALID_HANDLE_VALUE;
	pe->dosHeader = (IMAGE_DOS_HEADER*)imageBase; // cast
	pe->ntHeader = (IMAGE_NT_HEADERS*)(((PBYTE)imageBase) + pe->dosHeader->e_lfanew);
	pe->optHeader = &pe->ntHeader->OptionalHeader;
	if (isMemoryMapped) {
		pe->baseAddress = imageBase;
	}
	else {
		pe->baseAddress = (PVOID)pe->optHeader->ImageBase;
	}
	pe->dataDir = pe->optHeader->DataDirectory;
	pe->sectionHeaders = (IMAGE_SECTION_HEADER*)(((PBYTE)pe->optHeader) + pe->ntHeader->FileHeader.SizeOfOptionalHeader);
	DWORD exportRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportRVA == 0) {
		pe->exportDirectory = NULL;
		pe->exportedNames = NULL;
		pe->exportedFunctions = NULL;
		pe->exportedOrdinals = NULL;
	}
	else {
		pe->exportDirectory = (IMAGE_EXPORT_DIRECTORY*)PE_RVA_to_Addr(pe, exportRVA);
		pe->exportedNames = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNames);
		pe->exportedFunctions = (LPDWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfFunctions);
		pe->exportedOrdinals = (LPWORD)PE_RVA_to_Addr(pe, pe->exportDirectory->AddressOfNameOrdinals);
		pe->exportedNamesLength = pe->exportDirectory->NumberOfNames;
	}
	pe->relocations = NULL;
	DWORD debugRVA = pe->dataDir[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	if (debugRVA == 0) {
		pe->debugDirectory = NULL;
	}
	else {
		pe->debugDirectory = (IMAGE_DEBUG_DIRECTORY*)PE_RVA_to_Addr(pe, debugRVA);
		if (pe->debugDirectory->Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
			pe->debugDirectory = NULL;
		}
		else {
			pe->codeviewDebugInfo = (PE_codeview_debug_info*)PE_RVA_to_Addr(pe, pe->debugDirectory->AddressOfRawData);
			if (pe->codeviewDebugInfo->signature != *((DWORD*)"RSDS")) {
				pe->debugDirectory = NULL;
				pe->codeviewDebugInfo = NULL;
			}
		}
	}
	return pe;
}

VOID PE_destroy(PE* pe)
{
	if (pe->relocations) {
		free(pe->relocations);
		pe->relocations = NULL;
	}
	free(pe);
}

BOOL FileExistsW(LPCWSTR szPath)
{
	DWORD dwAttrib = GetFileAttributesW(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL WriteFullFileW(LPCWSTR fileName, PBYTE fileContent, SIZE_T fileSize) {
	HANDLE hFile = CreateFileW(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	BOOL res = WriteFile(hFile, fileContent, (DWORD)fileSize, NULL, NULL);
	CloseHandle(hFile);
	return res;
}

BOOL HttpsDownloadFullFile(LPCWSTR domain, LPCWSTR uri, PBYTE* output, SIZE_T* output_size) {
	///wprintf_or_not(L"Downloading https://%s%s...\n", domain, uri);
	// Get proxy configuration
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
	WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
	BOOL proxySet = !(proxyConfig.fAutoDetect || proxyConfig.lpszAutoConfigUrl != NULL);
	DWORD proxyAccessType = proxySet ? ((proxyConfig.lpszProxy == NULL) ?
		WINHTTP_ACCESS_TYPE_NO_PROXY : WINHTTP_ACCESS_TYPE_NAMED_PROXY) : WINHTTP_ACCESS_TYPE_NO_PROXY;
	LPCWSTR proxyName = proxySet ? proxyConfig.lpszProxy : WINHTTP_NO_PROXY_NAME;
	LPCWSTR proxyBypass = proxySet ? proxyConfig.lpszProxyBypass : WINHTTP_NO_PROXY_BYPASS;

	// Initialize HTTP session and request
	HINTERNET hSession = WinHttpOpen(L"WinHTTP/1.0", proxyAccessType, proxyName, proxyBypass, 0);
	if (hSession == NULL) {
		printf("WinHttpOpen failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
	if (!hConnect) {
		printf("WinHttpConnect failed with error : 0x%x\n", GetLastError());
		return FALSE;
	}
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", uri, NULL,
		WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		return FALSE;
	}

	// Configure proxy manually
	if (!proxySet)
	{
		WINHTTP_AUTOPROXY_OPTIONS  autoProxyOptions;
		autoProxyOptions.dwFlags = proxyConfig.lpszAutoConfigUrl != NULL ? WINHTTP_AUTOPROXY_CONFIG_URL : WINHTTP_AUTOPROXY_AUTO_DETECT;
		autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
		autoProxyOptions.fAutoLogonIfChallenged = TRUE;

		if (proxyConfig.lpszAutoConfigUrl != NULL)
			autoProxyOptions.lpszAutoConfigUrl = proxyConfig.lpszAutoConfigUrl;

		WCHAR szUrl[MAX_PATH] = { 0 };
		swprintf_s(szUrl, _countof(szUrl), L"https://%ws%ws", domain, uri);

		WINHTTP_PROXY_INFO proxyInfo;
		WinHttpGetProxyForUrl(
			hSession,
			szUrl,
			&autoProxyOptions,
			&proxyInfo);

		WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, sizeof(proxyInfo));
		DWORD logonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_LOW;
		WinHttpSetOption(hRequest, WINHTTP_OPTION_AUTOLOGON_POLICY, &logonPolicy, sizeof(logonPolicy));
	}

	// Perform request
	BOOL bRequestSent;
	do {
		bRequestSent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	} while (!bRequestSent && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
	if (!bRequestSent) {
		return FALSE;
	}
	BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
	if (!bResponseReceived) {
		return FALSE;
	}

	// Read response
	DWORD dwAvailableSize = 0;
	DWORD dwDownloadedSize = 0;
	SIZE_T allocatedSize = 4096;
	if (!WinHttpQueryDataAvailable(hRequest, &dwAvailableSize))
	{
		return FALSE;
	}
	*output = (PBYTE)malloc(allocatedSize);
	*output_size = 0;
	while (dwAvailableSize)
	{
		while (*output_size + dwAvailableSize > allocatedSize) {
			allocatedSize *= 2;
			PBYTE new_output = (PBYTE)realloc(*output, allocatedSize);
			if (new_output == NULL)
			{
				return FALSE;
			}
			*output = new_output;
		}
		if (!WinHttpReadData(hRequest, *output + *output_size, dwAvailableSize, &dwDownloadedSize))
		{
			return FALSE;
		}
		*output_size += dwDownloadedSize;

		WinHttpQueryDataAvailable(hRequest, &dwAvailableSize);
	}
	PBYTE new_output = (PBYTE)realloc(*output, *output_size);
	if (new_output == NULL)
	{
		return FALSE;
	}
	*output = new_output;
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return TRUE;
}

BOOL DownloadPDB(GUID guid, DWORD age, LPCWSTR pdb_name_w, PBYTE* file, SIZE_T* file_size) {
	WCHAR full_pdb_uri[MAX_PATH] = { 0 };
	swprintf_s(full_pdb_uri, _countof(full_pdb_uri), L"/download/symbols/%s/%08X%04hX%04hX%016llX%X/%s", pdb_name_w, guid.Data1, guid.Data2, guid.Data3, _byteswap_uint64(*((DWORD64*)guid.Data4)), age, pdb_name_w);
	return HttpsDownloadFullFile(L"msdl.microsoft.com", full_pdb_uri, file, file_size);
}

BOOL DownloadPDBFromPE(PE* image_pe, PBYTE* file, SIZE_T* file_size) {
	WCHAR pdb_name_w[MAX_PATH] = { 0 };
	GUID guid = image_pe->codeviewDebugInfo->guid;
	DWORD age = image_pe->codeviewDebugInfo->age;
	MultiByteToWideChar(CP_UTF8, 0, image_pe->codeviewDebugInfo->pdbName, -1, pdb_name_w, _countof(pdb_name_w));
	return DownloadPDB(guid, age, pdb_name_w, file, file_size);
}

symbol_ctx* LoadSymbolsFromPE(PE* pe) {
	symbol_ctx* ctx = (symbol_ctx*)calloc(1, sizeof(symbol_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, NULL, 0);
	ctx->pdb_name_w = (LPWSTR)calloc(size_needed, sizeof(WCHAR));
	MultiByteToWideChar(CP_UTF8, 0, pe->codeviewDebugInfo->pdbName, -1, ctx->pdb_name_w, size_needed);
	if (!FileExistsW(ctx->pdb_name_w)) {
		printf("Symbol file does not exist!\n");
		return NULL;
		PBYTE file;
		SIZE_T file_size;
		BOOL res = DownloadPDBFromPE(pe, &file, &file_size);
		if (!res) {
			free(ctx);
			return NULL;
		}
		WriteFullFileW(ctx->pdb_name_w, file, file_size);
		free(file);
	}
	else {
		//TODO : check if exisiting PDB corresponds to the file version
	}
	DWORD64 asked_pdb_base_addr = 0x140000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1337000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	//DWORD64 asked_pdb_base_addr = 0x1c0000000; // ntos baseAddress from Debugging at pe = ... -> 0x0000000140000000 ; ci base -> 0x00000001c0000000
	DWORD pdb_image_size = MAXDWORD;
	HANDLE cp = GetCurrentProcess();
	//if (!SymInitialize(cp, NULL, FALSE)) {
	if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		//if (!SymInitializeW(cp, ctx->pdb_name_w, FALSE)) {
		printf("Failed SymInitialize\n");
		free(ctx);
		return NULL;
	}
	ctx->sym_handle = cp;

	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
	DWORD64 addr = (DWORD64)pe->baseAddress;
	//addr -= 0x13ECC9000;
	//DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	DWORD64 pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, addr, pdb_image_size, NULL, 0);

	//printf("tmp\n");
	while (pdb_base_addr == 0) {
		DWORD err = GetLastError();
		if (err == ERROR_SUCCESS)
			printf("Success\n");
			break;
		if (err == ERROR_FILE_NOT_FOUND) {
			printf("PDB file not found\n");
			SymUnloadModule(cp, asked_pdb_base_addr);//TODO : fix handle leak
			SymCleanup(cp);
			free(ctx);
			return NULL;
		}
		asked_pdb_base_addr += 0x100000;
		//pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, asked_pdb_base_addr, pdb_image_size, NULL, 0);
		pdb_base_addr = SymLoadModuleExW(cp, NULL, ctx->pdb_name_w, NULL, (DWORD64)pe->baseAddress, pdb_image_size, NULL, 0);
	}
	ctx->pdb_base_addr = pdb_base_addr;
	printf("PDB base address: 0x%llx\n", ctx->pdb_base_addr);
	return ctx;
}

symbol_ctx* LoadSymbolsFromImageFile(LPCWSTR image_file_path) {
	PVOID image_content = ReadFullFileW(image_file_path);
	PE* pe = PE_create(image_content, FALSE);
	symbol_ctx* ctx = LoadSymbolsFromPE(pe);
	PE_destroy(pe);
	free(image_content);
	return ctx;
}

DWORD GetFieldOffset(symbol_ctx* ctx, LPCSTR struct_name, LPCWSTR field_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, struct_name, &si.si);
	if (!res) {
		DWORD err = GetLastError();
		printf("SymGetTypeFromName failed: sym_handle: 0x%llx, pdb_base_addr: 0x%llx, struct_name: %s, Err: %d\n", ctx->sym_handle, ctx->pdb_base_addr, struct_name, err);
		return 0;
	}

	TI_FINDCHILDREN_PARAMS* childrenParam = (TI_FINDCHILDREN_PARAMS*)calloc(1, sizeof(TI_FINDCHILDREN_PARAMS));
	if (childrenParam == NULL) {
		printf("calloc failed\n");
		return 0;
	}

	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_GET_CHILDRENCOUNT, &childrenParam->Count);
	if (!res) {
		printf("SymGetTypeInfo failed\n");
		return 0;
	}
	TI_FINDCHILDREN_PARAMS* ptr = (TI_FINDCHILDREN_PARAMS*)realloc(childrenParam, sizeof(TI_FINDCHILDREN_PARAMS) + childrenParam->Count * sizeof(ULONG));
	if (ptr == NULL) {
		printf("realloc failed\n");
		free(childrenParam);
		return 0;
	}
	childrenParam = ptr;
	res = SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, si.si.TypeIndex, TI_FINDCHILDREN, childrenParam);
	DWORD offset = 0;
	for (ULONG i = 0; i < childrenParam->Count; i++) {
		ULONG childID = childrenParam->ChildId[i];
		WCHAR* name = NULL;
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_SYMNAME, &name);
		if (wcscmp(field_name, name)) {
			continue;
		}
		SymGetTypeInfo(ctx->sym_handle, ctx->pdb_base_addr, childID, TI_GET_OFFSET, &offset);
		break;
	}
	free(childrenParam);
	printf("Offset of %S in %s: %d\n", field_name, struct_name, offset);
	return offset;
}
void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	if (ctx == NULL) {
		return;
	}

	if (ctx->sym_handle != NULL && ctx->pdb_base_addr != 0) {
		// Only unload this specific module
		if (!SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr)) {
			printf("SymUnloadModule failed: %d\n", GetLastError());
		}

		// Don't call SymCleanup here - it terminates the symbol handler
		// SymCleanup should only be called when you're completely done with symbols
	}

	// Delete the PDB file if requested
	if (delete_pdb && ctx->pdb_name_w != NULL) {
		DeleteFileW(ctx->pdb_name_w);
	}

	// Free allocated memory
	if (ctx->pdb_name_w != NULL) {
		free(ctx->pdb_name_w);
		ctx->pdb_name_w = NULL;
	}

	// Free the context structure itself
	free(ctx);
}
void CleanupSymbolHandler(HANDLE symHandle) {
	if (symHandle != NULL) {
		if (!SymCleanup(symHandle)) {
			printf("SymCleanup failed: %d\n", GetLastError());
		}
	}
}
/*void UnloadSymbols(symbol_ctx* ctx, BOOL delete_pdb) {
	SymUnloadModule(ctx->sym_handle, ctx->pdb_base_addr);
	SymCleanup(ctx->sym_handle);
	if (delete_pdb) {
		DeleteFileW(ctx->pdb_name_w);
	}
	free(ctx->pdb_name_w);
	ctx->pdb_name_w = NULL;
	free(ctx);
}*/

DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO symbolInfo = { 0 };
	symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
	symbolInfo.MaxNameLen = MAX_SYM_NAME;

	// Use SymFromName to look up symbols (including functions)
	if (SymFromName(ctx->sym_handle, symbol_name, &symbolInfo)) {
		return symbolInfo.Address - ctx->pdb_base_addr;
	}
	else {
		DWORD err = GetLastError();
		printf("SymFromName failed for '%s': error %d (0x%x)\n", symbol_name, err, err);

		// Try as a type (for backward compatibility)
		SYMBOL_INFO_PACKAGE si = { 0 };
		si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		si.si.MaxNameLen = sizeof(si.name);

		if (SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si)) {
			return si.si.Address - ctx->pdb_base_addr;
		}

		return 0;
	}
}
/*DWORD64 GetSymbolOffset(symbol_ctx* ctx, LPCSTR symbol_name) {
	SYMBOL_INFO_PACKAGE si = { 0 };
	si.si.SizeOfStruct = sizeof(SYMBOL_INFO);
	si.si.MaxNameLen = sizeof(si.name);
	BOOL res = SymGetTypeFromName(ctx->sym_handle, ctx->pdb_base_addr, symbol_name, &si.si);
	if (res) {
		return si.si.Address - ctx->pdb_base_addr;
	}
	else {
		DWORD err = GetLastError();
		printf("SymGetTypeFromName failed: sym_handle: 0x%llx, pdb_base_addr: 0x%llx, symbol_name: %s, err: %d\n", ctx->sym_handle, ctx->pdb_base_addr, symbol_name, err);
		return 0;
	}
}*/

typedef struct _INIT {
	CHAR identifier[4];
	DWORD NtBaseOffset;
	DWORD KPROCDirectoryTableBaseOffset;
	DWORD EPROCActiveProcessLinksOfsset;
	DWORD EPROCUniqueProcessIdOffset;
} INIT, * PINIT;

unsigned long long GetAndInsertSymbol(const char* str, symbol_ctx* symCtx, DWORD64 offset, BOOLEAN useOffset) {
	size_t strLen = strlen(str);
	if (strLen >= 32) {
		printf("Maximum string size reached...\n");
		return 0x0;
	}
	if (SymbolsArrayIndex >= SymbolsArrayAllocationSize) {
		printf("Maximum reached...\n");
		return 0x0;
	}
	PSYMBOL CurrSymbolInArray = (PSYMBOL)((PINIT)SymbolsArray + sizeof(INIT));

	if (!useOffset) {
		offset = GetSymbolOffset(symCtx, str);
	}

	memcpy(CurrSymbolInArray[SymbolsArrayIndex].name, std::move(str), strLen);
	CurrSymbolInArray[SymbolsArrayIndex].offset = offset;
	printf("Inserted: %s at: 0x%llx\n", CurrSymbolInArray[SymbolsArrayIndex].name, CurrSymbolInArray[SymbolsArrayIndex].offset);

	totalCopiedSize += strLen;
	SymbolsArrayIndex++;

	return offset;
}

BOOL AddInitData(DWORD NtBaseOffset, DWORD KPROCDirectoryTableBaseOffset, DWORD EPROCActiveProcessLinksOfsset, DWORD EPROCUniqueProcessIdOffset) {
	PINIT Data = (PINIT)SymbolsArray;
	memcpy(Data[0].identifier, "INIT", 4);
	Data[0].NtBaseOffset					= NtBaseOffset;
	Data[0].KPROCDirectoryTableBaseOffset	= KPROCDirectoryTableBaseOffset;
	Data[0].EPROCActiveProcessLinksOfsset	= EPROCActiveProcessLinksOfsset;
	Data[0].EPROCUniqueProcessIdOffset		= EPROCUniqueProcessIdOffset;
	return true;
}

DWORD64 GetKernelBase(_In_ std::string name) {
	/* Gets the base address (VIRTUAL ADDRESS) of a module in kernel address space */
	// Defining EnumDeviceDrivers() and GetDeviceDriverBaseNameA() parameters
	LPVOID lpImageBase[1024]{};
	DWORD lpcbNeeded{};
	int drivers{};
	char lpFileName[1024]{};
	DWORD64 imageBase{};
	// Grabs an array of all of the device drivers
	BOOL success = EnumDeviceDrivers(
		lpImageBase,
		sizeof(lpImageBase),
		&lpcbNeeded
	);
	// Makes sure that we successfully grabbed the drivers
	if (!success)
	{
		printf("Unable to invoke EnumDeviceDrivers()!\n");
		return 0;
	}
	// Defining number of drivers for GetDeviceDriverBaseNameA()
	drivers = lpcbNeeded / sizeof(lpImageBase[0]);
	// Parsing loaded drivers
	for (int i = 0; i < drivers; i++) {
		// Gets the name of the driver
		GetDeviceDriverBaseNameA(
			lpImageBase[i],
			lpFileName,
			sizeof(lpFileName) / sizeof(char)
		);
		// Compares the indexed driver and with our specified driver name
		//printf("[DriverName] {%s} == {%s}\n", lpFileName, name.c_str());
		if (!strcmp(name.c_str(), lpFileName)) {
			imageBase = (DWORD64)lpImageBase[i];
			//Logger::InfoHex("Found Image Base for " + name, imageBase);
			//printf("Found Image Base for %s 0x%lu\n", name.c_str(), imageBase);
			break;
		}
	}
	return imageBase;
}

/*void CheckPageStatus(void* address) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(address, &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
			std::cout << "Page is commited in memory." << std::endl;
		}
		else {
			std::cout << "Page is not in memory." << std::endl;
		}
	}
	else {
		std::cout << "VirtualQuery failed." << std::endl;
	}
}*/
void CheckPageStatus(void* address) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(address, &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
			PSAPI_WORKING_SET_EX_INFORMATION wsInfo = { 0 };
			wsInfo.VirtualAddress = address;

			if (QueryWorkingSetEx(GetCurrentProcess(), &wsInfo, sizeof(wsInfo))) {
				if (wsInfo.VirtualAttributes.Valid) {
					std::cout << "Page is in memory." << std::endl;
				}
				else {
					std::cout << "Page is swapped out (not in memory)." << std::endl;
				}
			}
			else {
				std::cout << "QueryWorkingSetEx failed." << std::endl;
			}
		}
		else {
			std::cout << "Page is not committed." << std::endl;
		}
	}
	else {
		std::cout << "VirtualQuery failed." << std::endl;
	}
}

void HexDump(void* pMemory, size_t size) {
	unsigned char* p = (unsigned char*)pMemory;

	for (size_t i = 0; i < size; i += 16) {  // Process 16 bytes per line
		printf("%08X  ", (unsigned int)i);   // Print offset

		// Print hex bytes
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size)
				printf("%02X ", p[i + j]);
			else
				printf("   ");  // Padding for alignment
		}

		printf(" | ");  // Separator

		// Print ASCII representation
		for (size_t j = 0; j < 16; j++) {
			if (i + j < size) {
				unsigned char c = p[i + j];
				printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
			}
		}

		printf(" |\n");
	}
}

// Use this version to safely work with memory manipulated by the driver
void CheckModifiedMemory(PVOID address, size_t size) {
	PVOID base = (PVOID)((unsigned long long)address & 0xfffffffffffff000);
	printf("Checking memory at base: 0x%p\n", base);

	// Just read, don't modify permissions with VirtualProtect
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(base, &mbi, sizeof(mbi))) {
		printf("Memory protection: 0x%lx\n", mbi.Protect);
		printf("Memory state: %s\n",
			mbi.State == MEM_COMMIT ? "COMMIT" :
			mbi.State == MEM_RESERVE ? "RESERVE" : "FREE");
	}

	// Read directly from memory without changing permissions
	__try {
		printf("Memory content (first 16 bytes):\n");
		unsigned char* p = (unsigned char*)base;

		for (size_t i = 0; i < size; i += 16) {  // Process 16 bytes per line
			printf("%08X  ", (unsigned int)i);   // Print offset

			// Print hex bytes
			for (size_t j = 0; j < 16; j++) {
				if (i + j < size)
					printf("%02X ", p[i + j]);
				else
					printf("   ");  // Padding for alignment
			}

			printf(" | ");  // Separator

			// Print ASCII representation
			for (size_t j = 0; j < 16; j++) {
				if (i + j < size) {
					unsigned char c = p[i + j];
					printf("%c", (c >= 32 && c <= 126) ? c : '.');  // Printable ASCII or dot
				}
			}

			printf(" |\n");
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("Exception when reading memory: 0x%lx\n", GetExceptionCode());
	}
}

#include <thread>
#include <atomic>
// Debug relay shared memory structure - must match kernel side
#define DBG_RELAY_MAPPING_NAME L"NewWorldDbgRelay"
#define DBG_RELAY_BUFFER_SIZE (512 * 1024)  // 512KB buffer for debug messages

typedef struct _DBG_RELAY_HEADER {
	volatile ULONG WriteOffset;    // Current write position by kernel
	volatile ULONG ReadOffset;     // Current read position by user-mode
	volatile ULONG EventCounter;   // Incremented when new data is available
	volatile BOOLEAN Overflow;     // Set when buffer has overflowed
} DBG_RELAY_HEADER, * PDBG_RELAY_HEADER;

typedef struct _DBG_RELAY_MEMORY {
	DBG_RELAY_HEADER Header;
	char Buffer[DBG_RELAY_BUFFER_SIZE];
} DBG_RELAY_MEMORY, * PDBG_RELAY_MEMORY;

// Global flag to control debugging thread
std::atomic<bool> g_debugThreadRunning(false);

// Function to monitor debug relay and print to console
void MonitorDebugRelay() {
	// Open the shared memory section
	HANDLE hMapFile = OpenFileMappingW(
		FILE_MAP_READ | FILE_MAP_WRITE,  // Read/write access
		FALSE,                           // Do not inherit the name
		DBG_RELAY_MAPPING_NAME           // Mapping name
	);

	if (hMapFile == NULL) {
		std::cerr << "Could not open debug relay mapping: " << GetLastError() << std::endl;
		return;
	}

	// Map the view of the file
	PDBG_RELAY_MEMORY pBuf = (PDBG_RELAY_MEMORY)MapViewOfFile(
		hMapFile,                       // Handle to map object
		FILE_MAP_READ | FILE_MAP_WRITE, // Read/write permission
		0, 0,                           // FileOffsetHigh, FileOffsetLow
		sizeof(DBG_RELAY_MEMORY)        // Number of bytes to map
	);

	if (pBuf == NULL) {
		std::cerr << "Could not map view of debug relay: " << GetLastError() << std::endl;
		CloseHandle(hMapFile);
		return;
	}

	std::cout << "Debug monitor active. Messages from kernel driver will appear here." << std::endl;

	ULONG lastEventCount = pBuf->Header.EventCounter;

	// Set the read offset to the current write offset to only show new messages
	pBuf->Header.ReadOffset = pBuf->Header.WriteOffset;

	while (g_debugThreadRunning) {
		// Check if there's new data by comparing event counters
		if (pBuf->Header.EventCounter != lastEventCount) {
			lastEventCount = pBuf->Header.EventCounter;

			// Process any available data
			while (pBuf->Header.ReadOffset != pBuf->Header.WriteOffset) {
				// Get current position
				ULONG readOffset = pBuf->Header.ReadOffset;

				// Read until null terminator or end of buffer
				std::string message;
				while (readOffset != pBuf->Header.WriteOffset) {
					char c = pBuf->Buffer[readOffset];
					readOffset = (readOffset + 1) % DBG_RELAY_BUFFER_SIZE;

					if (c == '\0') {
						break;  // End of message
					}
					message += c;
				}

				// Update read offset atomically
				pBuf->Header.ReadOffset = readOffset;

				// Print the message if not empty
				if (!message.empty()) {
					std::cout << message;
				}
			}
		}

		// Sleep briefly to avoid consuming too much CPU
		Sleep(10);
	}

	// Clean up
	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);

	std::cout << "Debug monitor stopped." << std::endl;
}

// Function to start the debug monitor
void StartDebugMonitor() {
	if (!g_debugThreadRunning.exchange(true)) {
		std::thread monitorThread(MonitorDebugRelay);
		monitorThread.detach();  // Let it run independently
	}
}

// Function to stop the debug monitor
void StopDebugMonitor() {
	g_debugThreadRunning = false;
	// Give it some time to clean up
	Sleep(100);
}

int main() {
	// ntoskrnl.exe symbols
	LPTSTR ntoskrnlPath;
	TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
	_tcscat_s(g_ntoskrnlPath, _countof(g_ntoskrnlPath), TEXT("C:\\Windows\\System32\\ntoskrnl.exe")); //ntmarta
	ntoskrnlPath = g_ntoskrnlPath;
	symbol_ctx* sym_ctxNtskrnl = LoadSymbolsFromImageFile(ntoskrnlPath);

	if (sym_ctxNtskrnl == NULL) {
		printf("Symbols for ntoskrnl.exe not available, download failed, aborting...\n");
		exit(1);
	}
	printf("ntoskrnl pdb base addr: %llx\n", sym_ctxNtskrnl->pdb_base_addr);
	printf("ntoskrnl pdb name: %ls\n", sym_ctxNtskrnl->pdb_name_w);
	printf("ntoskrnl sym handle: %p\n", sym_ctxNtskrnl->sym_handle);

	size_t NumSymbols = 7; // TODO Handle mapping size, currently its so few we'll stay below 1 page 4096 Bytes
	SymbolsArrayAllocationSize = sizeof(INIT);
	SymbolsArrayAllocationSize += NumSymbols * sizeof(SYMBOL); // TODO: Change to new Var: TotalAllocationSize
	printf("[*] Requesting %zu Bytes of Memory\n", SymbolsArrayAllocationSize);
	auto start = std::chrono::high_resolution_clock::now();

	HANDLE hMapFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SymbolsArrayAllocationSize, MAPPING_NAME);
	if (!hMapFile) {
		printf("[-] Failed to create file mapping: %d", GetLastError());
		return 1;
	}

	SymbolsArray = (VOID*)MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, SymbolsArrayAllocationSize);
	if (!SymbolsArray) {
		printf("[-] Failed to map view of file: %d\n", GetLastError());
		CloseHandle(hMapFile);
		return 1;
	}

	if (SymbolsArray == NULL) {
		printf("[-] Symbols Array could not be allocated\n");
		return 1;
	}
	totalAllocationSize += SymbolsArrayAllocationSize;

	unsigned long long ntBase = GetKernelBase("ntoskrnl.exe"); // DWORD64
	unsigned long long eprocUniqueProcessId = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"UniqueProcessId");
	unsigned long long eprocActiveProcessLinks = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"ActiveProcessLinks");
	unsigned long long kprocDirectoryTableBase = GetFieldOffset(sym_ctxNtskrnl, "_KPROCESS", L"DirectoryTableBase");
	AddInitData(ntBase, eprocUniqueProcessId, eprocActiveProcessLinks, kprocDirectoryTableBase);

	//PVOID sourceVA = malloc(4096);
	PVOID sourceVA = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	DWORD sourcePID = GetCurrentProcessId();

	unsigned long long KeServiceDescriptorTableOffset = GetAndInsertSymbol("KeServiceDescriptorTable", sym_ctxNtskrnl, 0, false);
	GetAndInsertSymbol("SymbolsAddr", sym_ctxNtskrnl, (unsigned long long)sourceVA, true);
	GetAndInsertSymbol("ntBase", sym_ctxNtskrnl, ntBase, true);
	GetAndInsertSymbol("eprocUniqueProcessId", sym_ctxNtskrnl, eprocUniqueProcessId, true);
	GetAndInsertSymbol("eprocActiveProcessLinks", sym_ctxNtskrnl, eprocActiveProcessLinks, true);
	GetAndInsertSymbol("kprocDirectoryTableBase", sym_ctxNtskrnl, kprocDirectoryTableBase, true);
	unsigned long long VADRoot = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"VadRoot");
	unsigned long long StartingVpn1 = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"StartingVpn");
	unsigned long long EndingVpn1 = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD_SHORT", L"EndingVpn");
	unsigned long long Left = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"Left");
	unsigned long long Right = GetFieldOffset(sym_ctxNtskrnl, "_RTL_BALANCED_NODE", L"Right");
	GetAndInsertSymbol("VADRoot", sym_ctxNtskrnl, VADRoot, true);
	GetAndInsertSymbol("StartingVpn", sym_ctxNtskrnl, StartingVpn1, true);
	GetAndInsertSymbol("EndingVpn", sym_ctxNtskrnl, EndingVpn1, true);
	GetAndInsertSymbol("Left", sym_ctxNtskrnl, Left, true);
	GetAndInsertSymbol("Right", sym_ctxNtskrnl, Right, true);
	unsigned long long MMVADSubsection = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD", L"Subsection");
	unsigned long long MMVADControlArea = GetFieldOffset(sym_ctxNtskrnl, "_MMVAD", L"ControlArea"); // actually at Off: 0x0 and its _CONTROL_AREA*
	unsigned long long MMVADCAFilePointer = GetFieldOffset(sym_ctxNtskrnl, "_CONTROL_AREA", L"FilePointer");
	unsigned long long FILEOBJECTFileName = GetFieldOffset(sym_ctxNtskrnl, "_FILE_OBJECT", L"FileName");
	printf("MMVADSubsection: 0x%llx\n", MMVADSubsection);
	printf("MMVADControlArea: 0x%llx\n", MMVADControlArea);
	printf("MMVADCAFilePointer: 0x%llx\n", MMVADCAFilePointer);
	printf("FILEOBJECTFileName: 0x%llx\n", FILEOBJECTFileName);
	GetAndInsertSymbol("MMVADSubsection", sym_ctxNtskrnl, MMVADSubsection, true);
	GetAndInsertSymbol("MMVADControlArea", sym_ctxNtskrnl, MMVADControlArea, true);
	GetAndInsertSymbol("MMVADCAFilePointer", sym_ctxNtskrnl, MMVADCAFilePointer, true);
	GetAndInsertSymbol("FILEOBJECTFileName", sym_ctxNtskrnl, FILEOBJECTFileName, true);
	unsigned long long EPROCImageFileName = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"ImageFileName");
	printf("EPROCImageFileName: 0x%llx\n", EPROCImageFileName);
	GetAndInsertSymbol("EPROCImageFileName", sym_ctxNtskrnl, EPROCImageFileName, true);
	unsigned long long MmPfnDatabase = GetAndInsertSymbol("MmPfnDatabase", sym_ctxNtskrnl, 0, false);
	GetAndInsertSymbol("SourceVA", sym_ctxNtskrnl, (unsigned long long)sourceVA, true);
	GetAndInsertSymbol("SourcePID", sym_ctxNtskrnl, (DWORD)sourcePID, true);
	printf("SourceVA: 0x%llx\n", sourceVA);
	printf("SourcePID: %d\n", (DWORD)sourcePID);

	unsigned long long PEB = GetFieldOffset(sym_ctxNtskrnl, "_EPROCESS", L"Peb");
	unsigned long long PEBLdr = GetFieldOffset(sym_ctxNtskrnl, "_PEB", L"Ldr");
	unsigned long long LdrListHead = GetFieldOffset(sym_ctxNtskrnl, "_PEB_LDR_DATA", L"InMemoryOrderModuleList");
	unsigned long long LdrListEntry = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"InMemoryOrderLinks");
	unsigned long long LdrBaseDllName = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"BaseDllName");
	unsigned long long LdrBaseDllBase = GetFieldOffset(sym_ctxNtskrnl, "_LDR_DATA_TABLE_ENTRY", L"DllBase"); 
	unsigned long long KeInvalidateAllCaches = GetAndInsertSymbol("KeInvalidateAllCaches", sym_ctxNtskrnl, 0, false);
	GetAndInsertSymbol("PEB", sym_ctxNtskrnl, PEB, true);
	GetAndInsertSymbol("PEBLdr", sym_ctxNtskrnl, PEBLdr, true);
	GetAndInsertSymbol("LdrListHead", sym_ctxNtskrnl, LdrListHead, true);
	GetAndInsertSymbol("LdrListEntry", sym_ctxNtskrnl, LdrListEntry, true);
	GetAndInsertSymbol("LdrBaseDllName", sym_ctxNtskrnl, LdrBaseDllName, true);
	GetAndInsertSymbol("LdrBaseDllBase", sym_ctxNtskrnl, LdrBaseDllBase, true);
	printf("PEB: 0x%llx\n", PEB);
	printf("PEBLdr: 0x%llx\n", PEBLdr);
	printf("LdrListHead: 0x%llx\n", LdrListHead);
	printf("LdrListEntry: 0x%llx\n", LdrListEntry);
	printf("LdrBaseDllName: 0x%llx\n", LdrBaseDllName);
	printf("LdrBaseDllBase: 0x%llx\n", LdrBaseDllBase);

	// ntmarta.dll symbols
	UnloadSymbols(sym_ctxNtskrnl, false);
	LPTSTR ntmartaPath;
	TCHAR g_ntmartaPath[MAX_PATH] = { 0 };
	_tcscat_s(g_ntmartaPath, _countof(g_ntmartaPath), TEXT("C:\\Windows\\System32\\ntmarta.dll")); //ntmarta
	ntmartaPath = g_ntmartaPath;
	symbol_ctx* sym_ctxNtmarta = LoadSymbolsFromImageFile(ntmartaPath);

	if (sym_ctxNtmarta == NULL) {
		printf("Symbols for ntmarta.dll not available, download failed, aborting...\n");
		exit(1);
	}
	printf("marta pdb base addr: %llx\n", sym_ctxNtmarta->pdb_base_addr);
	printf("marta pdb name: %ls\n", sym_ctxNtmarta->pdb_name_w);
	printf("marta sym handle: %p\n", sym_ctxNtmarta->sym_handle);
	unsigned long long TargetVA = GetSymbolOffset(sym_ctxNtmarta, "MartaSetKernelRights");
	
	GetAndInsertSymbol("TargetVA", sym_ctxNtmarta, TargetVA, true);
	printf("TargetVA: 0x%llx\n", TargetVA);

	printf("[*] Section available: Total Size Allocated: %d Bytes | Total Size Copied: %d Bytes\n\t[+] Waiting for driver to read...\n", totalAllocationSize, totalCopiedSize);
	HexDump((PVOID)((PINIT)SymbolsArray + sizeof(INIT)), SymbolsArrayAllocationSize);
	//HexDump((PVOID*)sourceVA + 0x950, 10);
	printf("\n--------\n");

	int ch;
	ch = getchar();

	// Start the debug monitor in a separate thread
	StartDebugMonitor();

	// Stop the debug monitor before exiting
	StopDebugMonitor();

	DWORD oldProtect;
	BOOLEAN vProtect = false;
	PVOID base = 0x0;
	while (true) {
		ch = getchar();

		if (ch == '\n')  // Skip empty Enter presses
			continue;

		if (ch == 'x' || ch == 'X')
			break;

		//__invlpg(sourceVA);
		//VirtualProtect()
		base = (PVOID)((unsigned long long)sourceVA & 0xfffffffffffff000);
		CheckModifiedMemory(base, 4096);
		//vProtect = VirtualProtect(base, 4096, PAGE_READWRITE, &oldProtect);
		//if (!VirtualProtect) {
		//	printf("[-] VirtualProtect failed: %d\n", GetLastError());
		//} else {
		//	printf("[+] VirtualProtect succeeded\n");
		//}
		//printf("Base: 0x%llx\n", base);
		//HexDump((PVOID)base, 100);
		//if (vProtect) {
		//	if (VirtualProtect(base, 4096, oldProtect, &oldProtect)) {
		//		printf("Restored old protection: 0x%lx\n", oldProtect);
		//	} else {
		//		printf("[-] Failed to restore old protection: %d\n", GetLastError());
		//	}
		//} else {
		//	printf("[-] Can not restore old protection\n");
		//}

		// Flush remaining characters in the buffer until newline
		while ((ch = getchar()) != '\n' && ch != EOF);
	}

	UnmapViewOfFile(SymbolsArray);
	CloseHandle(hMapFile);
	return 0;
}
