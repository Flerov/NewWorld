#pragma once
#include "main.h"

NTSTATUS DriverDispatcher(PDEVICE_OBJECT pDeviceObject, PIRP pIrp);
void DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DeviceDispatcher(PDEVICE_CONTEXT pDeviceContext, PIRP pIrp);
NTSTATUS SpyHookRemove(BOOL fReset, PDWORD pdCount);
void SpyWriteReset(PSPY_PROTOCOL psp);
void SpyHookCleanup(void);
DWORD SpyHookExchange(void);
BOOL SpyHookPause(BOOL fPause);
NTSTATUS SpyHookWait(void);
void SpyHookReset(void);
LONG SpyHookRelease(void);
NTSTATUS SpyDispatcher(PDEVICE_CONTEXT pDeviceContext,DWORD dCode,PVOID pInput,DWORD dInput,PVOID pOutput,DWORD dOutput,PDWORD pdInfo);
BOOL SpyMemoryPageEntry(PVOID pVirtual, PSPY_PAGE_ENTRY pspe);
VOID VirtToPhys(unsigned long long addr, PEPROCESS TargetProcess, unsigned long long cr3, BOOLEAN log);
