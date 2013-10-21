#include <windows.h>
#include "HotPatch.h"
#include <Winternl.h>
#include "patch1.h"


extern LIST_ENTRY _PsLoadedModuleList ;
extern NTSTATUS RtlEnterCriticalSection(RTL_CRITICAL_SECTION* crit);
extern NTSTATUS RtlLeaveCriticalSection(RTL_CRITICAL_SECTION* crit);
extern NTSTATUS LdrUnloadDll(HANDLE module);
RTL_CRITICAL_SECTION LdrpLoaderLock;
#define FLG_HOTPATCH_ACTIVE 1

LIST_ENTRY LdrpHotPatchList;
ULONG LdrpHotpatchCount;
LIST_ENTRY LdrpHotpatchModuleInfoList; //todo : check the type

//TODO check it
LIST_ENTRY* RtlFindRtlPatchHeader(LIST_ENTRY LdrpHotPatchList, PLDR_DATA_TABLE_ENTRY  LdrData)
{
    LIST_ENTRY* HotPatchList1 ;
    HotPatchList1 = LdrpHotPatchList.Blink ;
    while (HotPatchList1 != &LdrpHotPatchList)
    {
        if (*(ULONG*)HotPatchList1 + 0x2c == (ULONG)LdrData)
        {
        return HotPatchList1 ;
        }
        HotPatchList1 = HotPatchList1->Blink;
    }
    return NULL;
}

BOOLEAN LdrpHotpatchModuleInfoRemoveCallback(void* arg1, void* arg2)
{
    return RtlFreeHotPatchData((PRTL_PATCH_HEADER)((DWORD*)arg2 - 0x38));
}

void RtlTripleListInitialize(LIST_ENTRY* list,  void*, int flags)
{
    //todo: not implement
}

NTSTATUS LdrHotPatchRoutine(hotpatch_param param)
{
    NTSTATUS status;
    RtlEnterCriticalSection(&LdrpLoaderLock);
    bool entered = true;
     bool patched = false;

    PTEB teb = (PTEB)__readfsbyte(0x18);
    DWORD hotpatch_info = *((DWORD*)teb->ProcessEnvironmentBlock + 0x50);
    if ( !hotpatch_info )
    {
        RtlTripleListInitialize(&LdrpHotpatchModuleInfoList, LdrpHotpatchModuleInfoRemoveCallback, 0);
        *((DWORD*)teb->ProcessEnvironmentBlock + 0x50) = (DWORD)&LdrpHotpatchModuleInfoList;
    }
    //check new.dll is loaded or not ? old.dll?
    LIST_ENTRY* ModuleList = teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* temp = ModuleList;
    bool find = false;
    while(temp != &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList)
    {
        if( temp->Flink != NULL &&  RtlEqualUnicodeString(&param.TargetName, &((LDR_DATA_TABLE_ENTRY*)temp)->FullDllName, true) )
        {
            find = true;
        }
        temp = temp->Flink;
    }
    if ( find == false )
    {
        status = STATUS_DLL_NOT_FOUND;
        goto end;
    }

    if ( !LdrpHotpatchCount )
    {
        LdrpHotPatchList.Blink = &LdrpHotPatchList; // ?
    }

    HANDLE new_dll;
    status = LdrLoadDll(NULL, 0, &param.SourceName, &new_dll);// load new dll, new_module is the start address of new.dll
#define STATUS_UNSUCCESSFUL 0xC0000001   
    PLDR_DATA_TABLE_ENTRY new_module_info = NULL;
     if ( (status & 0x80000000u) == 0 )
     {
        LIST_ENTRY* temp = ModuleList;
        while(temp != &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList)
        {
            PLDR_DATA_TABLE_ENTRY temp2 = (PLDR_DATA_TABLE_ENTRY)temp;
            if( temp->Flink != NULL &&  new_dll == temp2->DllBase )
            {
                new_module_info = temp2;
                break;
            }
            temp = temp->Flink;
        }
        if( !new_module_info )
        {
            status = STATUS_UNSUCCESSFUL;
            goto end;
        }
  
        PHOTPATCH_HEADER section_data = RtlGetHotpatchHeader(new_dll);// point to hot section in new.dll
        if ( !section_data )                       // not find
        {
            status = 0xC000007Bu;
            goto end;
        }

        PRTL_PATCH_HEADER  patch_header = (PRTL_PATCH_HEADER)RtlFindRtlPatchHeader(LdrpHotPatchList, new_module_info);
        if ( patch_header )//the patch is already installed
        {
            if ( !patch_header->CodeInfo->Flags & FLG_HOTPATCH_ACTIVE )  //patch is not active
            {
            status = RtlReadHookInformation(patch_header);
            if ( (status & 0x80000000u) != 0 )
                goto end;
            }
        }
        else
        {
            status = RtlCreateHotPatch(patch_header,section_data,new_module_info,param.shci.Flags);
            if ( (status & 0x80000000u) != 0 )
                goto end;
            status = LdrpSetupHotpatch(patch_header);
            if ( (status & 0x80000000u) != 0 )
            {
                RtlFreeHotPatchData(patch_header);
                goto end;
            }
            //TOdo has call NTopenfile
             
            //apply hotpatch
            status = LdrpApplyHotPatch(patch_header, param.shci.Flags);
            if ( patched )
            {
                if ( (status & 0x80000000u) != 0 )
                {
                    RtlFreeHotPatchData(patch_header);
                    patched = false;
                }
                else
                {
                    // add into patch list
                    /*patch_header->NextPatch->PatchList.Flink = patch_header->TargetLdrDataTableEntry->PatchInformation = patch_header;
                    patch_header->PatchList.Flink = &LdrpHotPatchList;
                    patch_header->PatchList.Blink = LdrpHotPatchList;
                    LdrpHotPatchList->PatchList.Flink = patch_header;
                    LdrpHotPatchList = patch_header;
                    ++LdrpHotpatchCount;*/
                    //RtlTripleListInsert(&LdrpHotpatchModuleInfoList, patch_header->);
                }
            }
        }

     }
end:
     if ( entered )
          RtlLeaveCriticalSection(&LdrpLoaderLock);
     if ( !patched  && new_dll )
         LdrUnloadDll(new_dll);
     ULONG  RegionSize = 0;
     return NtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&param, &RegionSize, MEM_RELEASE);
}
