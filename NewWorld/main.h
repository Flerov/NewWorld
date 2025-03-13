#pragma once
#include <ntdef.h>
#include <ntddk.h>

// =================================================================
// BASIC TYPES
// =================================================================
typedef unsigned char       BYTE, * PBYTE, ** PPBYTE;
typedef unsigned short      WORD, * PWORD, ** PPWORD;
typedef unsigned long       DWORD, * PDWORD, ** PPDWORD;
typedef unsigned __int64    QWORD, * PQWORD, ** PPQWORD;
typedef int                 BOOL, * PBOOL, ** PPBOOL;
typedef void** PPVOID;

// -----------------------------------------------------------------

#define BYTE_               sizeof (BYTE)
#define WORD_               sizeof (WORD)
#define DWORD_              sizeof (DWORD)
#define QWORD_              sizeof (QWORD)
#define BOOL_               sizeof (BOOL)
#define PVOID_              sizeof (PVOID)
#define HANDLE_             sizeof (HANDLE)
#define PHYSICAL_ADDRESS_   sizeof (PHYSICAL_ADDRESS)

// =================================================================
// MACROS
// =================================================================

#define DRV_MODULE          NewWorld
#define DRV_NAME            NW Windows 2025 Spy Device
#define DRV_COMPANY         Me
#define DRV_AUTHOR          Me
#define DRV_EMAIL           me@me.me
#define DRV_PREFIX          NW

#define _DRV_DEVICE(_name)  \\Device\\     ## _name
#define _DRV_LINK(_name)    \\DosDevices\\ ## _name
#define _DRV_PATH(_name)    \\\\.\\        ## _name

#define DRV_DEVICE              _DRV_DEVICE (DRV_MODULE)
#define DRV_LINK                _DRV_LINK   (DRV_MODULE)
#define DRV_PATH                _DRV_PATH   (DRV_MODULE)
#define DRV_EXTENSION           sys

// -----------------------------------------------------------------

#define _CSTRING(_text) #_text
#define CSTRING(_text) _CSTRING (_text)

#define _USTRING(_text) L##_text
#define USTRING(_text) _USTRING (_text)

#define PRESET_UNICODE_STRING(_symbol,_buffer) \
        UNICODE_STRING _symbol = \
            { \
            sizeof (USTRING (_buffer)) - sizeof (WORD), \
            sizeof (USTRING (_buffer)), \
            USTRING (_buffer) \
            };

// -----------------------------------------------------------------
typedef NTSTATUS(NTAPI* NTPROC)();

// =================================================================
// CONSTANTS
// =================================================================

#define PAGE_SHIFT               12
#define PTI_SHIFT                12
#define PDI_SHIFT                22

#define SPY_CALLS           0x00000100 // max api call nesting level
#define SPY_NAME            0x00000400 // max object name length
#define SPY_HANDLES         0x00001000 // max number of handles
#define SPY_NAME_BUFFER     0x00100000 // object name buffer size
#define SPY_DATA_BUFFER     0x00100000 // protocol data buffer size

// -----------------------------------------------------------------

#define FILE_DEVICE_SPY     0x8000
#define SPY_IO_BASE         0x0800

// -----------------------------------------------------------------

#define SDT_SYMBOLS_NT4     0xD3
#define SDT_SYMBOLS_NT5     0xF8
#define SDT_SYMBOLS_MAX     SDT_SYMBOLS_NT5

// =================================================================
// INTEL X86 MACROS & CONSTANTS
// =================================================================

#define X86_PAGE_MASK (0 - (1 << PAGE_SHIFT))
#define X86_PAGE(_p)  (((DWORD) (_p) & X86_PAGE_MASK) >> PAGE_SHIFT)

#define X86_PDI_MASK  (0 - (1 << PDI_SHIFT))
#define X86_PDI(_p)   (((DWORD) (_p) & X86_PDI_MASK) >> PDI_SHIFT)

#define X86_PTI_MASK  ((0 - (1 << PTI_SHIFT)) & ~X86_PDI_MASK)
#define X86_PTI(_p)   (((DWORD) (_p) & X86_PTI_MASK) >> PTI_SHIFT)

#define X86_OFFSET(_p,_m) ((DWORD_PTR) (_p) & ~(_m))
#define X86_OFFSET_4M(_p) X86_OFFSET (_p, X86_PDI_MASK)
#define X86_OFFSET_4K(_p) X86_OFFSET (_p, X86_PDI_MASK|X86_PTI_MASK)

#define X86_PAGE_4M   (1 << PDI_SHIFT)
#define X86_PAGE_4K   (1 << PTI_SHIFT)

#define X86_PAGES_4M  (1 << (32 - PDI_SHIFT))
#define X86_PAGES_4K  (1 << (32 - PTI_SHIFT))

// -----------------------------------------------------------------

#define X86_PAGES         0xC0000000
#define X86_PTE_ARRAY     ((PX86_PE) X86_PAGES)
#define X86_PDE_ARRAY     (X86_PTE_ARRAY + (X86_PAGES >> PTI_SHIFT))

// =================================================================
// FUNCTION TYPES
// =================================================================

typedef NTSTATUS(NTAPI* NTPROC) ();
typedef NTPROC* PNTPROC;
#define NTPROC_ sizeof (NTPROC)

typedef VOID(NTAPI* NTPROC_VOID) ();
typedef NTPROC_VOID* PNTPROC_VOID;
#define NTPROC_VOID_ sizeof (NTPROC_VOID)

typedef BOOLEAN(NTAPI* NTPROC_BOOLEAN) ();
typedef NTPROC_BOOLEAN* PNTPROC_BOOLEAN;
#define NTPROC_BOOLEAN_ sizeof (NTPROC_BOOLEAN)

// https://gist.github.com/mvankuipers
//typedef struct _PML4E
//{
//	union
//	{
//		struct
//		{
//			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
//			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
//			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
//			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PDPT.
//			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PDPT.
//			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
//			ULONG64 Ignored1 : 1;
//			ULONG64 PageSize : 1;             // Must be 0 for PML4E.
//			ULONG64 Ignored2 : 4;
//			ULONG64 PageFrameNumber : 36;     // The page frame number of the PDPT of this PML4E.
//			ULONG64 Reserved : 4;
//			ULONG64 Ignored3 : 11;
//			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
//		};
//		ULONG64 Value;
//	};
//} PML4E, * PPML4E;
//static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");
typedef struct _PML4E
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // [0] Must be 1 if entry is valid.
			ULONG64 ReadWrite : 1;            // [1] 0 = Read-only, 1 = Read/Write.
			ULONG64 UserSupervisor : 1;       // [2] 0 = Kernel-only, 1 = User-mode accessible.
			ULONG64 PageWriteThrough : 1;     // [3] Write-through caching enabled.
			ULONG64 PageCacheDisable : 1;     // [4] Caching disabled.
			ULONG64 Accessed : 1;             // [5] Set when the page is accessed.
			ULONG64 Ignored1 : 1;             // [6] Ignored by hardware.
			ULONG64 PageSize : 1;             // [7] Must be 0 for PML4E (since it's the top-level page table).
			ULONG64 Ignored2 : 3;             // [8-10] Ignored by hardware.
			ULONG64 Reserved : 4;             // [11-14] Reserved.
			ULONG64 PageFrameNumber : 36;     // [15-50] The 36-bit page frame number (points to the next level).
			ULONG64 Reserved2 : 3;            // [51-53] Reserved for alignment.
			ULONG64 ProtectionKey : 4;        // [54-57] Protection keys (if enabled).
			ULONG64 Ignored3 : 2;             // [58-59] Ignored by hardware.
			ULONG64 ExecuteDisable : 1;       // [60] If 1, prevents instruction fetches (NX bit).
			ULONG64 Ignored4 : 3;             // [61-63] Ignored by hardware.
		};
		ULONG64 Value;
	};
} PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

//typedef struct _PDPTE
//{
//	union
//	{
//		struct
//		{
//			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
//			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
//			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
//			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PD.
//			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PD.
//			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
//			ULONG64 Ignored1 : 1;
//			ULONG64 PageSize : 1;             // If 1, this entry maps a 1GB page.
//			ULONG64 Ignored2 : 4;
//			ULONG64 PageFrameNumber : 36;     // The page frame number of the PD of this PDPTE.
//			ULONG64 Reserved : 4;
//			ULONG64 Ignored3 : 11;
//			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
//		};
//		ULONG64 Value;
//	};
//} PDPTE, * PPDPTE;
//static_assert(sizeof(PDPTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

// https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html
// https://www.unknowncheats.me/forum/anti-cheat-bypass/668915-mmmapiospace-vulnerable-drivers.html

// PAT-Table
//rdmsr 0x277 (windbg-command)
// msr[277] = 00070106`00070106
// 00070106 (First 32bits)
// 00070106 (Second 32 bits)

// Encoding		| Mnemonic
//  0x00          Uncacheable (UC)     -> it forces the CPU to always access memory directly, without using any cache.
//  0x01		  Write Combining (WC) -> allows the processor to combine multiple writes to adjacent memory locations into one larger write. This improves performance for certain types of memory access patterns, such as for graphics memory or network buffers. However, the memory is still treated as uncached in some respects, which means reads from this memory are not cached
//  0x02          Reserved*
//  0x03          Reserved*
//  0x04          Write Through (WT)   -> any write operation to this memory is written to both the cache and the memory (RAM) at the same time. This ensures that the data in memory is always up-to-date, but it could reduce performance due to more frequent writes to RAM
//  0x05          Write Protected (WP) -> any writes to the memory are not allowed, which makes the memory read-only. This is used for memory areas that should not be modified (such as code segments)
//  0x06          Write Back (WB)      -> any writes are initially stored in the cache and written back to the main memory (RAM) later when necessary. This reduces memory traffic and improves performance.
//  0x07          Uncached (UC-)       -> explicitly marks the memory as uncached, meaning that neither reads nor writes are cached. This could be used in specific low-latency memory regions, like device buffers or critical data.
//  0x08-0xFF     Reserved*

// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf
// 11.12.3 Selecting a Memory Type from the PAT
// PAT PCD PWT | PAT Entry
//  0   0   0      PAT0 -> 0x00
//  0   0   1      PAT1 -> 0x01
//  0   1   0      PAT2 -> 0x02
//  0   1   1      PAT3 -> 0x03
//  1   0   0      PAT4 -> 0x04
//  1   0   1      PAT5 -> 0x05
//  1   1   0      PAT6 -> 0x06
//  1   1   1      PAT7 -> 0x07
// 
// A Large_Page can not reference  PA7-PA4 since there is no PTE: ONLY VALID are PA0-PA3 in that case
// 63    59 58 56 55    51 50 48 47    43 42 40 39    35 34 32 31    27 26 24 23    19 18 16 15    11 10  8 7      3 2   0
// Reserved  PA7  Reserved  PA6  Reserved  PA5  Reserved  PA4  Reserved  PA3  Reserved  PA2  Reserved  PA1  Reserved  PA0

//  00000    000    00000   111   00000    001   00000    110    00000   000    00000   111    00000   001    00000   110  (example read > r @msr 0x277)
typedef struct _PDPTE
{
	union
	{
		struct
		{
			//-PAT - INDEX: is made up of the: PAT, PCD, PWT bits
			ULONG64 Present : 1;              // [0] Must be 1 if entry is valid.
			ULONG64 ReadWrite : 1;            // [1] 0 = Read-only, 1 = Read/Write.
			ULONG64 UserSupervisor : 1;       // [2] 0 = Kernel-only, 1 = User-mode accessible.
			ULONG64 PageWriteThrough : 1;     // [3] Write-through caching enabled.
			ULONG64 PageCacheDisable : 1;     // [4] Caching disabled.
			ULONG64 Accessed : 1;             // [5] Set when the page is accessed.
			ULONG64 Ignored1 : 1;             // [6] Ignored by hardware.
			ULONG64 PageSize : 1;             // [7] 1 = Maps a 1GB page, 0 = Points to a page directory.
			ULONG64 Ignored2 : 4;             // [8-10] Ignored by hardware.      
			// https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf
			// 11.12.3 Selecting a Memory Type from the PAT
			union
			{
				struct
				{
					ULONG64 PAT : 1;             // [12] Page Attribute Table (only for 1GB pages).
					ULONG64 ReservedHigh : 18;  // [13-29] Reserved if PageSize=1.
					ULONG64 PageFrameNumber1GB : 18; // [30-47] The 18-bit page frame number (for 1GB pages).
				};
				struct
				{
					ULONG64 PageFrameNumber4KB : 36; // [12-47] The 36-bit page frame number (for 4KB page directories).
				};
			};

			ULONG64 Reserved : 2;             // [48-49] Must be 0.
			ULONG64 Ignored3 : 7;             // [50-56] Ignored by hardware.
			ULONG64 ProtectionKey : 4;        // [57-60] Available for protection keys.
			ULONG64 Ignored4 : 1;             // [61] Must be ignored by hardware.
			ULONG64 Ignored5 : 1;             // [62] Must be ignored by hardware.
			ULONG64 ExecuteDisable : 1;       // [63] If 1, prevents execution (NX bit).
		};
		ULONG64 Value;
	};
} PDPTE, * PPDPTE;

//typedef struct _PDE
//{
//	union
//	{
//		struct
//		{
//			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
//			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
//			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
//			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access PT.
//			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access PT.
//			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
//			ULONG64 Dirty : 1;				  // Dirty
//			ULONG64 PageSize : 1;             // If 1, this entry maps a 2MB page.
//			ULONG64 GlobalPage : 1;			  // Global Page
//			ULONG64 Available : 3;			  // Available to programmer
//			ULONG64 PageFrameNumber : 36;     // The page frame number of the PT of this PDE.
//			ULONG64 Reserved : 4;
//			ULONG64 Ignored3 : 11;
//			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
//		};
//		ULONG64 Value;
//	};
//} PDE, * PPDE;
//static_assert(sizeof(PDE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");
typedef struct _PDE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // [0] Must be 1 if the entry is valid.
			ULONG64 ReadWrite : 1;            // [1] 0 = Read-only, 1 = Read/Write.
			ULONG64 UserSupervisor : 1;       // [2] 0 = Kernel-only, 1 = User-mode accessible.
			ULONG64 PageWriteThrough : 1;     // [3] Write-through caching enabled.
			ULONG64 PageCacheDisable : 1;     // [4] Caching disabled.
			ULONG64 Accessed : 1;             // [5] Set when the page is accessed.
			ULONG64 Dirty : 1;                // [6] Only valid for 2 MB pages.
			ULONG64 PageSize : 1;             // [7] If 1, maps a 2 MB page instead of a page table.
			ULONG64 Global : 1;               // [8] Only valid if PageSize = 1.
			ULONG64 Available1 : 1;            // [9-11] Available for OS use.
			ULONG64 Available2 : 1;            // [9-11] Available for OS use.
			ULONG64 Available3 : 1;            // [9-11] Available for OS use.

			union
			{
				struct
				{
					ULONG64 PAT : 1;          // [12] Page Attribute Table bit (Only valid for 2 MB pages).
					ULONG64 ReservedHigh : 17; // [13-29] Reserved if PageSize=1.
					ULONG64 PageFrameNumber : 18; // [30-47] The 18-bit page frame number (for 2 MB pages).
				};
				struct
				{
					ULONG64 PageFrameNumber4KB : 36; // [12-47] The 36-bit page frame number (for 4 KB pages).
				};
			};

			ULONG64 Reserved : 2;             // [48-49] Must be 0.
			ULONG64 Ignored1 : 7;             // [50-56] Ignored.
			ULONG64 ProtectionKey : 4;        // [57-60] Available for protection keys.
			ULONG64 Ignored2 : 1;             // [61] Must be ignored by hardware.
			ULONG64 Ignored3 : 1;             // [62] Must be ignored by hardware.
			ULONG64 ExecuteDisable : 1;       // [63] If 1, prevents execution (NX bit).
		};
		ULONG64 Value;
	};
} PDE, * PPDE;

//typedef struct _PTE
//{
//	union
//	{
//		struct
//		{
//			ULONG64 Present : 1;              // Must be 1, region invalid if 0.
//			ULONG64 ReadWrite : 1;            // If 0, writes not allowed.
//			ULONG64 UserSupervisor : 1;       // If 0, user-mode accesses not allowed.
//			ULONG64 PageWriteThrough : 1;     // Determines the memory type used to access the memory.
//			ULONG64 PageCacheDisable : 1;     // Determines the memory type used to access the memory.
//			ULONG64 Accessed : 1;             // If 0, this entry has not been used for translation.
//			ULONG64 Dirty : 1;                // If 0, the memory backing this page has not been written to.
//			ULONG64 PageAccessType : 1;       // Determines the memory type used to access the memory.
//			ULONG64 Global : 1;                // If 1 and the PGE bit of CR4 is set, translations are global.
//			ULONG64 Ignored2 : 3;
//			ULONG64 PageFrameNumber : 36;     // The page frame number of the backing physical page.
//			ULONG64 Reserved : 4;
//			ULONG64 Ignored3 : 7;
//			ULONG64 ProtectionKey : 4;         // If the PKE bit of CR4 is set, determines the protection key.
//			ULONG64 ExecuteDisable : 1;       // If 1, instruction fetches not allowed.
//		};
//		ULONG64 Value;
//	};
//} PTE, * PPTE;
typedef struct _PTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;              // [0] Must be 1 if entry is valid.
			ULONG64 ReadWrite : 1;            // [1] 0 = Read-only, 1 = Read/Write.
			ULONG64 UserSupervisor : 1;       // [2] 0 = Kernel-only, 1 = User-mode accessible.
			ULONG64 PageWriteThrough : 1;     // [3] Write-through caching enabled.                       - PWT (needed for PAT-Index)
			ULONG64 PageCacheDisable : 1;     // [4] Caching disabled.                                    - PCD (needed for PAT-Index)
			ULONG64 Accessed : 1;             // [5] Set when the page is accessed.						  
			ULONG64 Dirty : 1;                // [6] Set if the page has been written to.                 
			ULONG64 PageAccessType : 1;       // [7] Determines the memory access type (merged with PAT). - PAT
			ULONG64 Global : 1;               // [8] If 1, translation is global (requires PGE in CR4).
			ULONG64 Ignored2 : 3;             // [9-11] Ignored by hardware.
			ULONG64 PageFrameNumber : 36;     // [12-47] The 36-bit page frame number (physical page).
			ULONG64 Reserved : 4;             // [48-51] Reserved for alignment.
			ULONG64 ProtectionKey : 4;        // [52-55] Protection Key (enabled with PKE in CR4).
			ULONG64 Ignored3 : 7;             // [56-62] Ignored by hardware.
			ULONG64 ExecuteDisable : 1;       // [63] If 1, prevents instruction fetches (NX bit).
		};
		ULONG64 Value;
	};
} PTE, * PPTE;
static_assert(sizeof(PTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PHYSICAL_1GB {
	union {
		struct {
			ULONG64 Offset : 30;      // Offset within a 1GB page
			ULONG64 PageNumber : 18;  // Page Frame Number (PFN)
			ULONG64 Reserved : 16;    // Reserved bits
		};
		ULONG64 Value;
	};
} PHYSICAL_1GB, * PPHYSICAL_1GB;

typedef struct _PHYSICAL_2MB {
	union {
		struct {
			ULONG64 Offset : 21; // Offset within a 2 MB page
			ULONG64 PageNumber : 27; // Page Frame Number (PFN)
			ULONG64 Reserved : 16; // Unused or reserved bits
		};
		ULONG64 Value;
	};
} PHYSICAL_2MB, * PPHYSICAL_2MB;
typedef struct _PHYSICAL_4KB {
	union {
		struct {
			ULONG64 Offset : 12;         // Offset within a 4 KB page
			ULONG64 PageNumber : 36;     // Page Frame Number (PFN), supports 64-bit systems
			ULONG64 Reserved : 16;       // Reserved bits, may be used for future extensions
		};
		ULONG64 Value;
	};
} PHYSICAL_4KB, * PPHYSICAL_4KB;

// =================================================================
// INTEL X86 STRUCTURES, PART 2 OF 3
// =================================================================

typedef struct _X86_PDBR // page-directory base register (cr3)
{
	union
	{
		struct
		{
			DWORD dValue;            // packed value
		};
		struct
		{
			unsigned Reserved1 : 3;
			unsigned PWT : 1; // page-level write-through
			unsigned PCD : 1; // page-level cache disabled
			unsigned Reserved2 : 7;
			unsigned PFN : 20; // page-frame number
		};
	};
}
X86_PDBR, * PX86_PDBR, ** PPX86_PDBR;
#define X86_PDBR_ sizeof (X86_PDBR)

// -----------------------------------------------------------------

typedef struct _X86_PDE_4M // page-directory entry (4-MB page)
{
	union
	{
		struct
		{
			DWORD dValue;            // packed value
		};
		struct
		{
			unsigned P : 1; // present (1 = present)
			unsigned RW : 1; // read/write
			unsigned US : 1; // user/supervisor
			unsigned PWT : 1; // page-level write-through
			unsigned PCD : 1; // page-level cache disabled
			unsigned A : 1; // accessed
			unsigned D : 1; // dirty
			unsigned PS : 1; // page size (1 = 4-MB page)
			unsigned G : 1; // global page
			unsigned Available : 3; // available to programmer
			unsigned Reserved : 10;
			unsigned PFN : 10; // page-frame number
		};
	};
}
X86_PDE_4M, * PX86_PDE_4M, ** PPX86_PDE_4M;
#define X86_PDE_4M_ sizeof (X86_PDE_4M)

// -----------------------------------------------------------------

typedef struct _X86_PDE_4K // page-directory entry (4-KB page)
{
	union
	{
		struct
		{
			DWORD dValue;            // packed value
		};
		struct
		{
			unsigned P : 1; // present (1 = present)
			unsigned RW : 1; // read/write
			unsigned US : 1; // user/supervisor
			unsigned PWT : 1; // page-level write-through
			unsigned PCD : 1; // page-level cache disabled
			unsigned A : 1; // accessed
			unsigned Reserved : 1; // dirty
			unsigned PS : 1; // page size (0 = 4-KB page)
			unsigned G : 1; // global page
			unsigned Available : 3; // available to programmer
			unsigned PFN : 20; // page-frame number
		};
	};
}
X86_PDE_4K, * PX86_PDE_4K, ** PPX86_PDE_4K;
#define X86_PDE_4K_ sizeof (X86_PDE_4K)

// -----------------------------------------------------------------

typedef struct _X86_PTE_4K // page-table entry (4-KB page)
{
	union
	{
		struct
		{
			DWORD dValue;            // packed value
		};
		struct
		{
			unsigned P : 1; // present (1 = present)
			unsigned RW : 1; // read/write
			unsigned US : 1; // user/supervisor
			unsigned PWT : 1; // page-level write-through
			unsigned PCD : 1; // page-level cache disabled
			unsigned A : 1; // accessed
			unsigned D : 1; // dirty
			unsigned Reserved : 1;
			unsigned G : 1; // global page
			unsigned Available : 3; // available to programmer
			unsigned PFN : 20; // page-frame number
		};
	};
}
X86_PTE_4K, * PX86_PTE_4K, ** PPX86_PTE_4K;
#define X86_PTE_4K_ sizeof (X86_PTE_4K)

// -----------------------------------------------------------------

typedef struct _X86_PNPE // page not present entry
{
	union
	{
		struct
		{
			DWORD dValue;            // packed value
		};
		struct
		{
			unsigned P : 1; // present (0 = not present)
			unsigned Reserved1 : 9;
			unsigned PageFile : 1; // page swapped to pagefile
			unsigned Reserved2 : 21;
		};
	};
}
X86_PNPE, * PX86_PNPE, ** PPX86_PNPE;
#define X86_PNPE_ sizeof (X86_PNPE)

// -----------------------------------------------------------------

typedef struct _X86_PE // general page entry
{
	union
	{
		DWORD      dValue; // packed value
		X86_PDBR   pdbr;   // page-directory Base Register
		X86_PDE_4M pde4M;  // page-directory entry (4-MB page)
		X86_PDE_4K pde4K;  // page-directory entry (4-KB page)
		X86_PTE_4K pte4K;  // page-table entry (4-KB page)
		X86_PNPE   pnpe;   // page not present entry
	};
}
X86_PE, * PX86_PE, ** PPX86_PE;
#define X86_PE_ sizeof (X86_PE)

// -----------------------------------------------------------------

typedef struct _SPY_PAGE_ENTRY
{
	X86_PE pe;
	DWORD  dSize;
	BOOL   fPresent;
} SPY_PAGE_ENTRY, *PSPY_PAGE_ENTRY, **PPSPY_PAGE_ENTRY;
#define SPY_PAGE_ENTRY_ sizeof (SPY_PAGE_ENTRY)

// -----------------------------------------------------------------

typedef struct _SPY_CALL_INPUT
{
	BOOL  fFastCall;
	DWORD dArgumentBytes;
	PVOID pArguments;
	PBYTE pbSymbol;
	PVOID pEntryPoint;
}
SPY_CALL_INPUT, * PSPY_CALL_INPUT, ** PPSPY_CALL_INPUT;
#define SPY_CALL_INPUT_ sizeof (SPY_CALL_INPUT)

// -----------------------------------------------------------------

typedef struct _SPY_MEMORY_BLOCK
{
	union
	{
		PBYTE pbAddress;
		PVOID pAddress;
	};
	DWORD dBytes;
}
SPY_MEMORY_BLOCK, * PSPY_MEMORY_BLOCK, ** PPSPY_MEMORY_BLOCK;
#define SPY_MEMORY_BLOCK_ sizeof (SPY_MEMORY_BLOCK)

// -----------------------------------------------------------------

typedef struct _SPY_HOOK_ENTRY
{
	NTPROC Handler;
	PBYTE  pbFormat;
}
SPY_HOOK_ENTRY, * PSPY_HOOK_ENTRY, ** PPSPY_HOOK_ENTRY;
#define SPY_HOOK_ENTRY_ sizeof (SPY_HOOK_ENTRY)

typedef struct _SPY_CALL
{
	BOOL            fInUse;               // set if used entry
	HANDLE          hThread;              // id of calling thread
	PSPY_HOOK_ENTRY pshe;                 // associated hook entry
	PVOID           pCaller;              // caller's return address
	DWORD           dParameters;          // number of parameters
	DWORD           adParameters[1 + 256]; // result and parameters
}
SPY_CALL, * PSPY_CALL, ** PPSPY_CALL;
#define SPY_CALL_ sizeof (SPY_CALL)

typedef struct _SPY_HEADER
{
	LARGE_INTEGER liStart;  // start time
	DWORD         dRead;    // read data index
	DWORD         dWrite;   // write data index
	DWORD         dCalls;   // api usage count
	DWORD         dHandles; // handle count
	DWORD         dName;    // object name index
}
SPY_HEADER, * PSPY_HEADER, ** PPSPY_HEADER;
#define SPY_HEADER_ sizeof (SPY_HEADER)

typedef struct _SPY_PROTOCOL
{
	SPY_HEADER    sh;                            // protocol header
	HANDLE        ahProcesses[SPY_HANDLES];     // process id array
	HANDLE        ahObjects[SPY_HANDLES];     // handle array
	DWORD         adNames[SPY_HANDLES];     // name offsets
	WORD          awNames[SPY_NAME_BUFFER]; // name strings
	BYTE          abData[SPY_DATA_BUFFER]; // protocol data
}
SPY_PROTOCOL, * PSPY_PROTOCOL, ** PPSPY_PROTOCOL;
#define SPY_PROTOCOL_ sizeof (SPY_PROTOCOL)

typedef struct _DEVICE_CONTEXT
{
	PDRIVER_OBJECT  pDriverObject;        // driver object ptr
	PDEVICE_OBJECT  pDeviceObject;        // device object ptr
	KMUTEX          kmDispatch;           // ioctl dispatch mutex
	KMUTEX          kmProtocol;           // protocol access mutex
	DWORD           dLevel;               // nesting level
	DWORD           dMisses;              // number of misses
	SPY_CALL        SpyCalls[SPY_CALLS]; // api call contexts
	SPY_PROTOCOL    SpyProtocol;          // protocol control block
}
DEVICE_CONTEXT, * PDEVICE_CONTEXT, ** PPDEVICE_CONTEXT;
#define DEVICE_CONTEXT_ sizeof (DEVICE_CONTEXT)

// -----------------------------------------------------------------

#define MUTEX_INITIALIZE(_mutex) \
        KeInitializeMutex        \
            (&(_mutex), 0)

#define MUTEX_WAIT(_mutex)       \
        KeWaitForMutexObject     \
            (&(_mutex), Executive, KernelMode, FALSE, NULL)

#define MUTEX_RELEASE(_mutex)    \
        KeReleaseMutex           \
            (&(_mutex), FALSE)

// =================================================================
// API SERVICE STRUCTURES
// =================================================================

typedef struct _SYSTEM_SERVICE_TABLE
{
	/*000*/ PNTPROC ServiceTable;           // array of entry points
	/*004*/ PDWORD  CounterTable;           // array of usage counters
	/*008*/ DWORD   ServiceLimit;           // number of table entries
	/*00C*/ PBYTE   ArgumentTable;          // array of byte counts
	/*010*/
}
SYSTEM_SERVICE_TABLE,
* PSYSTEM_SERVICE_TABLE,
** PPSYSTEM_SERVICE_TABLE;
#define SYSTEM_SERVICE_TABLE_ \
        sizeof (SYSTEM_SERVICE_TABLE)

// -----------------------------------------------------------------

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	/*000*/ SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe (native api)
	/*010*/ SYSTEM_SERVICE_TABLE win32k;    // win32k.sys   (gdi/user)
	/*020*/ SYSTEM_SERVICE_TABLE Table3;    // not used
	/*030*/ SYSTEM_SERVICE_TABLE Table4;    // not used
	/*040*/
}
SERVICE_DESCRIPTOR_TABLE,
* PSERVICE_DESCRIPTOR_TABLE,
** PPSERVICE_DESCRIPTOR_TABLE;
#define SERVICE_DESCRIPTOR_TABLE_ \
        sizeof (SERVICE_DESCRIPTOR_TABLE)

// =================================================================
// EXTERNAL VARIABLES
// =================================================================
//extern PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
// TODO: New Prototype -> Map all offsets to exports of ntoskrnl into shared memory user-mode <-> kernel-mode
PSERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;
