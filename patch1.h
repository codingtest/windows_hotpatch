#ifndef PATCH_H
#define PATCH_H

#include <Windows.h>
#include "HotPatch.h"
#include <Winternl.h>

extern BOOLEAN RtlEqualUnicodeString(
  _In_  PCUNICODE_STRING String1,
  _In_  PCUNICODE_STRING String2,
  _In_  BOOLEAN CaseInSensitive
);

extern PIMAGE_NT_HEADERS RtlImageNtHeader(HANDLE module);

extern ULONG __cdecl DbgPrintEx(
  _In_  ULONG ComponentId,
  _In_  ULONG Level,
  _In_  PCSTR Format,
  ... 
);



NTSTATUS RtlCreateHotPatch(PRTL_PATCH_HEADER patch_header_out ,  //out
   PHOTPATCH_HEADER hotpatch_data ,
   PLDR_DATA_TABLE_ENTRY LdrData,
   NTSTATUS Flags);

NTSTATUS LdrpApplyHotPatch(PRTL_PATCH_HEADER patch_header, int flags);
NTSTATUS LdrpSetupHotpatch(PRTL_PATCH_HEADER patch_header);
NTSTATUS RtlInitializeHotPatch(PRTL_PATCH_HEADER patch_header, int flags);
BOOLEAN RtlFreeHotPatchData(PRTL_PATCH_HEADER patch_header);
NTSTATUS RtlReadHookInformation(PRTL_PATCH_HEADER patch_header);
NTSTATUS RtlpSingleRangeValidate(PRTL_PATCH_HEADER patch_header, PHOTPATCH_VALIDATION valarray);
NTSTATUS RtlpValidateTargetRanges(PRTL_PATCH_HEADER patch_header, bool flags);
NTSTATUS RtlpReadSingleHookInformation(PRTL_PATCH_HEADER patch_header, HOTPATCH_HOOK* HookArray,int flags1, size_t* pSize, DWORD* pHotpAddr);
PIMAGE_SECTION_HEADER RtlpFindSectionHeader(PIMAGE_NT_HEADERS nt_header, void* section_name);
HOTPATCH_HEADER *RtlGetHotpatchHeader(HANDLE module);
NTSTATUS RtlpValidateTargetRanges(PRTL_PATCH_HEADER patch_header, int flags);

extern BOOLEAN RtlFreeHeap(
  _In_      PVOID HeapHandle,
  _In_opt_  ULONG Flags,
  _In_      PVOID HeapBase
);

extern PVOID RtlAllocateHeap(
  _In_      PVOID HeapHandle,
  _In_opt_  ULONG Flags,
  _In_      SIZE_T Size
);


NTSTATUS NtFreeVirtualMemory(
  _In_     HANDLE ProcessHandle,
  _Inout_  PVOID *BaseAddress,
  _Inout_  PSIZE_T RegionSize,
  _In_     ULONG FreeType
);


typedef struct hotpatch_param{
    SYSTEM_HOTPATCH_CODE_INFORMATION shci;
    UNICODE_STRING SourceName;
    UNICODE_STRING TargetName;
} hotpatch_param;

extern NTSYSAPI 
NTSTATUS
NTAPI
LdrLoadDll(
  IN PWCHAR               PathToFile OPTIONAL,
  IN ULONG                Flags OPTIONAL,
  IN PUNICODE_STRING      ModuleFileName,
  OUT PHANDLE             ModuleHandle );


NTSTATUS LdrHotPatchRoutine(hotpatch_param param);

#endif PATCH_H