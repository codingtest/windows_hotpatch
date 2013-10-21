#include "patch1.h"
#include <windows.h>


NTSTATUS LdrpSetHotpatchProtection(PVOID Dllbase, int flags)
{
    //TODO: implement later
    return 0;
}
BOOLEAN RtlpValidatePeHeaderHash2(PRTL_PATCH_HEADER PatchHeader,
   PVOID DllBase)
{
    //TODO implement later
    return FALSE ;
}

NTSTATUS RtlpApplyRelocationFixups(PRTL_PATCH_HEADER patch_header, int flags)
{
    //todo implement later
    return 0;
}

BOOLEAN RtlpValidatePeChecksum(PRTL_PATCH_HEADER PatchHeader,
   PVOID DllBase)

{
    //TODO implement later
    return FALSE;
}

BOOLEAN RtlpFreeAtom(PVOID address)
{
    return RtlFreeHeap(GetProcessHeap(), 0, address);
}

PVOID RtlpAllocateHotpatchMemory(SIZE_T Size,ULONG Flags)
{
    RtlAllocateHeap(GetProcessHeap(),0,Size);
}

NTSTATUS RtlCreateHotPatch(PRTL_PATCH_HEADER patch_header_out ,  //out
   PHOTPATCH_HEADER hotpatch_data ,
   PLDR_DATA_TABLE_ENTRY LdrData,
   DWORD Flags) //check about the last param
{
    NTSTATUS ret;
    PRTL_PATCH_HEADER  patch_header = (PRTL_PATCH_HEADER)RtlpAllocateHotpatchMemory(sizeof(RTL_PATCH_HEADER),0);
    if( patch_header)
    {
         memset(patch_header, 0, sizeof(RTL_PATCH_HEADER));

         patch_header->HotpatchHeader = hotpatch_data;
         patch_header->PatchLdrDataTableEntry = LdrData;
         patch_header->PatchImageBase = (HMODULE)LdrData->DllBase;
         //patch_header->Hash128 = 0x8;
         patch_header->PatchList.Blink = (LIST_ENTRY*)patch_header ;
         patch_header->PatchList.Flink = (LIST_ENTRY*)patch_header ;
         patch_header->PatchFlags = Flags & 0xFFFFFFFE;
         PANSI_STRING target_dll;
         RtlInitAnsiString(target_dll, (PCSZ)((DWORD)LdrData->DllBase + hotpatch_data->TargetNameRva));
         NTSTATUS status = RtlAnsiStringToUnicodeString(&patch_header->TargetDllName, target_dll, 1);

        if ( (status & 0x80000000u) != 0 )
            RtlFreeHotPatchData(patch_header);
        else
            patch_header_out = patch_header;
        ret = status;
    }
    else
    {
        ret = STATUS_NO_MEMORY;
    }
    return ret;

}


NTSTATUS LdrpSetupHotpatch(PRTL_PATCH_HEADER patch_header)
{
    //seems the code has no meaning here
   /* PTEB teb = (PTEB)__readfsbyte(0x18);
    
    LIST_ENTRY* ModuleList = teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY* temp = ModuleList;
    bool find = false;
    while(temp != &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList)
    {
        if( temp->Flink != NULL &&  RtlpIsSameImage(patch_header, (PLDR_DATA_TABLE_ENTRY)temp) )
        {
            find = true;
            break;
        }
        temp = temp->Flink;
    }*/

    NTSTATUS result;

    if ( patch_header->TargetDllBase )
    {
        result = LdrpSetHotpatchProtection(patch_header->PatchLdrDataTableEntry->DllBase,0 );
        if ( (result & 0x80000000u) == 0 )
        {
            result = RtlInitializeHotPatch(patch_header, 0);
            LdrpSetHotpatchProtection(patch_header->PatchLdrDataTableEntry->DllBase,1 );
        }
    }
    else
    {
        result = STATUS_DLL_NOT_FOUND;
    }
    return result;

}

NTSTATUS LdrpApplyHotPatch(PRTL_PATCH_HEADER patch_header, int flags)
{
    NTSTATUS result;

    if ( patch_header->TargetDllBase )
    {
        result = LdrpSetHotpatchProtection(patch_header->PatchLdrDataTableEntry->DllBase,0 );
        if ( (result & 0x80000000u) == 0 )
        {
            result = RtlInitializeHotPatch(patch_header, 0);
            LdrpSetHotpatchProtection(patch_header->PatchLdrDataTableEntry->DllBase,1 );
        }
    }
    else
    {
        result = STATUS_DLL_NOT_FOUND;
    }
    return result;
}


NTSTATUS RtlInitializeHotPatch(PRTL_PATCH_HEADER patch_header, int flags)
{
  NTSTATUS result; 

  result = RtlpApplyRelocationFixups(patch_header, flags);
  if ( result >= 0 )
  {
    result = RtlpValidateTargetRanges(patch_header, 1);
    if ( result >= 0 )
      result = RtlReadHookInformation(patch_header);
  }
  return result;
}

bool RtlpValidateTargetModule(PRTL_PATCH_HEADER patch_header, PLDR_DATA_TABLE_ENTRY Ldrdata)
{
    ULONG method =  patch_header->HotpatchHeader->ModuleIdMethod;
    char* message = NULL;
    switch(method)
    {
    case HOTP_ID_None:
        DbgPrintEx(85, 2, "HOTP_ID_None\n");  //not support
        return true;
    case HOTP_ID_PeHeaderHash1:
        DbgPrintEx(85, 2, "HOTP_ID_PeHeaderHash1");  //not support
        return false;
    case HOTP_ID_PeHeaderHash2:
        DbgPrintEx(85, 2, "HOTP_ID_PeHeaderHash2");
        return RtlpValidatePeHeaderHash2(patch_header, Ldrdata->DllBase);
    case HOTP_ID_PeChecksum:
        return RtlpValidatePeChecksum(patch_header, Ldrdata->DllBase);
    case HOTP_ID_PeDebugSignature:
        DbgPrintEx(85, 2, "HOTP_ID_PeDebugSignature");  //not support
        return false;
    default:
        DbgPrintEx(85, 2, "Unrecognized");  //not support
        return false;

    }
}

bool RtlpIsSameImage(PRTL_PATCH_HEADER patch_header, PLDR_DATA_TABLE_ENTRY Ldrdata)
{
    bool ret = false;
    if ( RtlImageNtHeader((HANDLE)Ldrdata->DllBase) ) 
    {
        if ( RtlEqualUnicodeString(&patch_header->TargetDllName, &Ldrdata->FullDllName, true) 
            && RtlpValidateTargetModule(patch_header, Ldrdata) )
        {
            patch_header->PatchLdrDataTableEntry = Ldrdata;
            patch_header->TargetDllBase = (HMODULE)Ldrdata->DllBase;
            ret = true;
        }
    }
    return ret;
}


BOOLEAN RtlFreeHotPatchData(PRTL_PATCH_HEADER patch_header)
{
  if ( patch_header->CodeInfo )
     RtlpFreeAtom(patch_header->CodeInfo);
  if ( patch_header->TargetDllBase )
    NtClose(patch_header->TargetDllBase);
  RtlFreeUnicodeString(&patch_header->TargetDllName); 
  return RtlpFreeAtom(patch_header);
}


NTSTATUS RtlReadHookInformation(PRTL_PATCH_HEADER patch_header)
{
    PHOTPATCH_HEADER hotpatch_header = patch_header->HotpatchHeader;
    DWORD HookCount = hotpatch_header->HookCount;
    DWORD HookArrayRva = hotpatch_header->HookArrayRva;
    IMAGE_NT_HEADERS* NtHaader = RtlImageNtHeader(patch_header->PatchImageBase);
    if ( !HookCount )
    {
        DbgPrintEx(85, 0, "No hooks defined in hotpatch\n");
        return 0xC000007B;
    }
    DWORD image_size = NtHaader->OptionalHeader.SizeOfImage;
    if ( !HookArrayRva
    || HookArrayRva >= image_size
    || HookArrayRva + sizeof(HOTPATCH_HOOK) * HookCount >= image_size )
    {
        DbgPrintEx(85, 0, "Invalid hotpatch hook array pointer\n");
        return 0xC000007B;
    }
    PHOTPATCH_HOOK HookArray = (PHOTPATCH_HOOK)(HookArrayRva + (DWORD)patch_header->PatchImageBase);
    DbgPrintEx(85, 2, "Inserting %u hooks into target image\n", HookCount);
    DWORD totalMemory = 40 * (HookCount - 1) + 56;
    size_t Size;
    NTSTATUS status;
    int index = 0;
    if ( HookCount )
    {
        while ( 1 )
        {
             status = RtlpReadSingleHookInformation(patch_header, HookArray, 0, &Size, 0);
             if ( status < 0 )
                break;
             totalMemory += 2 * Size;
             if ( HookArray->ValidationRva )
              {
               /* status = RtlReadSingleHookValidation(patch_header, HookArray, 0, &Size, 0, 0, 0);
                if ( status < 0 )
                  return status;
                totalMemory += Size;*/
              }
             ++index;
             ++HookArray;
             if ( index >= HookCount )
                 goto LABEL1;
        }
    }
    else
    {
LABEL1:
        //TODO not finished
        PVOID hotpatch_addr = RtlpAllocateHotpatchMemory(totalMemory, 1);
        if ( hotpatch_addr )
        {
            //init the value
            if ( HookCount )
            {
                DWORD hookaddr = (DWORD)patch_header->TargetDllBase + HookArray->HookRva;
                int index = 0;
                /*while(1)
                {
                    index++;
                }*/
            }
        }
        else
        {
            status = STATUS_NO_MEMORY;
        }
    }
    return status;
}

NTSTATUS RtlpValidateTargetRanges(PRTL_PATCH_HEADER patch_header, bool flags)
{
    PHOTPATCH_HEADER hotpatch_header = patch_header->HotpatchHeader;
    DWORD  ValidationCount = hotpatch_header->ValidationCount;
    DWORD ValidationArrayRva  = hotpatch_header->ValidationArrayRva;
    IMAGE_NT_HEADERS* NtHaader = RtlImageNtHeader(patch_header->PatchImageBase);
    NTSTATUS status;
    if ( ! ValidationCount )
        return 0;
    if ( ValidationArrayRva )
    {
        DWORD image_size = NtHaader->OptionalHeader.SizeOfImage;
        if ( ValidationArrayRva < image_size )
        {
           if ( ValidationArrayRva + sizeof(HOTPATCH_VALIDATION) * ValidationCount < image_size )
           {
                PHOTPATCH_VALIDATION ValidatationArray = (PHOTPATCH_VALIDATION)(ValidationArrayRva + (DWORD)patch_header->PatchImageBase);
                int index = 0;
                PHOTPATCH_VALIDATION array = ValidatationArray;
                if ( ValidationCount )
                {
                    do {
                        if ( flags && array->OptionFlags == 1 )
                        {
                             DbgPrintEx(85, 2, "Skipping hook-specific validation range during global validation\n");
                        }
                        else
                        {
                             status = RtlpSingleRangeValidate(patch_header, array);
                             if ( status < 0 )
                             {
                                DbgPrintEx(85, 0, "Validation failed for global range %u of %u\n", index + 1, ValidationCount);
                                return status;
                             }
                        }
                        array++;
                        ++index;
                    }while(index < ValidationCount );
                }
                return 0;
           }
        }
    }
    DbgPrintEx(85, 0, "Invalid hotpatch validation array pointer\n");
    return 0xC000007B; //STATUS_INVALID_IMAGE_FORMAT
}


NTSTATUS RtlpSingleRangeValidate(PRTL_PATCH_HEADER patch_header, PHOTPATCH_VALIDATION valarray)
{
    DWORD SourceRva = valarray->SourceRva;
    WORD bytecount = valarray->ByteCount;
    DWORD targetrva = valarray->TargetRva;
    PIMAGE_NT_HEADERS nthead1 = RtlImageNtHeader(patch_header->PatchImageBase);
    PIMAGE_NT_HEADERS nthead2 = RtlImageNtHeader(patch_header->TargetDllBase);
    DWORD image_size = nthead1->OptionalHeader.SizeOfImage;
    NTSTATUS status;
    char* message = NULL;
    if ( SourceRva >= image_size || SourceRva + bytecount >= image_size )
    {
        message = "Invalid source hotpatch validation range\n";
        goto err_exit;
    }
    if ( RtlCompareMemory(SourceRva + patch_header->PatchImageBase, targetrva + patch_header->TargetDllBase, bytecount) == bytecount )
    {
        status = 0;
    }
    else
      {
        DbgPrintEx(
          85,
          2,
          "Validation failure. Source = %p, Target = %p, Size = %x\n",
          SourceRva + patch_header->PatchImageBase,
          targetrva + patch_header->TargetDllBase,
          bytecount);
        status = 0xC000003E;
      }

err_exit:
    DbgPrintEx(85, 0, message);
    return 0xC000007B;
}

NTSTATUS RtlpReadSingleHookInformation(PRTL_PATCH_HEADER patch_header, HOTPATCH_HOOK* HookArray,int flags1, size_t* pSize, DWORD* pHotpAddr)
{
    PIMAGE_NT_HEADERS ntheader_patch = RtlImageNtHeader(patch_header->PatchImageBase);
    if ( !ntheader_patch )
    {
         DbgPrintEx(85, 0, "Invalid hotpatch base address\n");
         return 0xC000007B;
    }
    PIMAGE_NT_HEADERS ntheader_target = RtlImageNtHeader(patch_header->TargetDllBase);
    if ( !ntheader_target )
    {
         DbgPrintEx(85, 0,  "Invalid target base address\n");
         return 0xC000007B;
    }
     DWORD targetimagesize = ntheader_target->OptionalHeader.SizeOfImage;
    if ( HookArray->HookRva >= targetimagesize )
    {
        DbgPrintEx(85, 0,  "Invalid hotpatch hook pointer\n");
        return 0xC000007B;
    }
    if ( HookArray->HookOptions & 0x8000 )
    {
        size_t size1 = patch_header->TargetDllBase < patch_header->PatchImageBase? \
            patch_header->PatchImageBase + ntheader_patch->OptionalHeader.SizeOfImage - patch_header->TargetDllBase :\
            patch_header->TargetDllBase + targetimagesize - patch_header->PatchImageBase;
        if ( size1 > 0x80000000 )
        {
          DbgPrintEx(85, 0, "Hotpatch loaded > 2GB from target image\n");
          return 0xC0000018u;
        }
    }
    DWORD  Hookaddr = HookArray->HookRva + (DWORD)patch_header->TargetDllBase;
    DWORD  Hotpaddr = HookArray->HotpRva + (DWORD)patch_header->PatchImageBase;
    size_t size = 0;
    WORD options = 0;
    switch(HookArray->HookOptions)
    {
    case HOTP_Hook_VA32: 
        *pSize = 4;
        if ( HookArray->HotpRva < ntheader_patch->OptionalHeader.SizeOfImage )
        {
          if ( !pHotpAddr )
            return 0;
          if ( flags1 >= 4 )
          {
            *pHotpAddr = Hotpaddr;
            return 0;
          }
          return 0xC0000023u;
        }
        
        DbgPrintEx(85, 0, "Invalid hotpatch relative address\n");
        return 0xC000007B;
    case HOTP_Hook_X86_JMP:
        options = HookArray->HookOptions & 0x1F;
        size = 5;
        if ( options > 5 )
          size = options;
        *pSize = size;
        if ( HookArray->HotpRva < ntheader_patch->OptionalHeader.SizeOfImage )
        {
            if ( !pHotpAddr )
            return 0;
            if ( flags1 >= size )
            {
                *pHotpAddr = 0xE9;  //?
                *(pHotpAddr + 1) = Hotpaddr - Hookaddr - 5;
                if ( *pSize > 5 )
                { //todo check it 
                  size_t v28 = *pSize - 5;
                  DWORD* v29 = pHotpAddr + 5;
                  do
                  {
                    *v29++ = -52;
                    --v28;
                  }
                  while ( v28 );
                }
                DbgPrintEx(
                  85,
                  2,
                  "\t%08I64X: jmp %08X (PC+%08X) {",
                  Hookaddr,
                  Hookaddr >> 32,
                  Hotpaddr,
                  Hotpaddr - Hookaddr - 5);
                int index = 0;
                if ( *pSize )
                {
                    do{
                      //  DbgPrintEx(85, 2, " %02X", *((DWORD)(index + Hookaddr)));
                        index++;
                    }
                    while ( index < *pSize );
                }
                DbgPrintEx(85, 2, " }\n");
                return 0;
            }
            return 0xC0000023u;
        }
        DbgPrintEx(85, 0, "Invalid hotpatch relative address\n");
        return 0xC000007B;
    case HOTP_Hook_X86_JMP2B:
        options = HookArray->HookOptions & 0x1F;
        size = options;
        if ( options <= 2 )
          size = 2;
        *pSize = size;
        if ( !pHotpAddr )
            return 0;
        if ( flags1 >= size )
        {//todo: check what it means
            *pHotpAddr = 0xEB;  //?
            *(pHotpAddr + 1) = HookArray->HotpRva & 0x0000FFFF;
             DWORD* v24 = pHotpAddr + 2;
            if ( *pSize > 2u )
            {
                DWORD v25 = *pSize - 2;
                do
                {
                    *v24++ = -52;
                    --v25;
                }
                while ( v25 );
            }
              return 0;
        }
        return 0xC0000023u;
    case HOTP_Hook_VA64:
        *pSize = 8;
        if ( !pHotpAddr )
          return 0;
        if ( flags1 >= 8 )
        {
          *pHotpAddr = Hotpaddr;
          return 0;
        }
        return 0xC0000023u;
    case HOTP_Hook_IA64_BRL:
        //TODO : not finished
        break;
    case HOTP_Hook_AMD64_IND:
        //TODO : not finished
        break;
    case HOTP_Hook_AMD64_CNT:
        //TODO : not finished
        break;
    default:
        DbgPrintEx(85, 0, "Invalid hook type specified\n");
        return 0xC0000002u;
    }
    *pSize = 2;
    if ( !pHotpAddr )
        return 0;
    if ( flags1 < 2 )
        return 0xC0000023u;
    *pHotpAddr = HookArray->HotpRva & 0x0000FFFF;  //low 4 byte
    return 0;
}

PIMAGE_SECTION_HEADER RtlpFindSectionHeader(PIMAGE_NT_HEADERS nt_header, void* section_name)
{
    PIMAGE_SECTION_HEADER ret = NULL;
    PIMAGE_SECTION_HEADER section_start = (PIMAGE_SECTION_HEADER)(&nt_header->OptionalHeader + nt_header->FileHeader.SizeOfOptionalHeader);
    if ( nt_header->FileHeader.NumberOfSections <= 0 )
        return NULL;
    for ( int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
    {
        
        if ( RtlCompareMemory(section_start, section_name, IMAGE_SIZEOF_SHORT_NAME) == IMAGE_SIZEOF_SHORT_NAME )
            ret = section_start;
        else
            section_start += sizeof(IMAGE_SECTION_HEADER);
    }
    return ret;
}


HOTPATCH_HEADER *RtlGetHotpatchHeader(HANDLE module)
{
    PIMAGE_NT_HEADERS nt_header = RtlImageNtHeader(module);
    PIMAGE_SECTION_HEADER  section_start;
    HOTPATCH_HEADER* result = NULL;
    if( nt_header == NULL )
        return NULL;
    section_start = (PIMAGE_SECTION_HEADER)RtlpFindSectionHeader(nt_header, ".hotp1  ");
    if ( section_start == 0 
        || (result = (HOTPATCH_HEADER*)((DWORD)module + section_start->VirtualAddress), section_start->Misc.PhysicalAddress < 0x50)
        || result->Signature != HOTP_SIGNATURE
        || result->Version != HOTP_VERSION_1 )
    result = NULL;
  return result;
}