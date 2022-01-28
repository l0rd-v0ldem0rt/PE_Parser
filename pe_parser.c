#include <stdio.h>
#include <windows.h>

int main(int argc, char **argv){

    char *dll = argv[1];

    printf("\n");
    printf("\n");
    printf("[+]+++++++++++++++++++++++++++++++++[+]\n");
    printf("[+]++++Author : Amankumar Badhel++++[+]\n");
    printf("[+]+++++++++++++++++++++++++++++++++[+]\n");
    printf("\n");
    printf("\n");
    HMODULE hKernel32;

    //hKernel32 = LoadLibraryA("kernel32.dll");
    
    hKernel32 = LoadLibraryA(dll);

    printf("hKernel32 : 0x%p : %s\n", hKernel32, hKernel32);

    //dos header
    PIMAGE_DOS_HEADER dos_header;

    dos_header = (PIMAGE_DOS_HEADER)hKernel32;

    printf("\n");
    printf("[+]++++NT Header++++[+]\n");
    printf("\n");
    printf("e_magic : 0x%X\n", dos_header->e_magic);
    printf("e_cblp : 0x%X\n", dos_header->e_cblp);
    printf("e_cp : 0x%X\n", dos_header->e_cp);
    printf("e_crlc : 0x%X\n", dos_header->e_crlc);
    printf("e_cparhdr : 0x%X\n", dos_header->e_cparhdr);
    printf("e_minalloc : 0x%X\n", dos_header->e_minalloc);
    printf("e_maxalloc : 0x%X\n", dos_header->e_maxalloc);
    printf("e_ss : 0x%X\n", dos_header->e_ss);
    printf("e_csum : 0x%X\n", dos_header->e_csum);
    printf("e_ip : 0x%X\n", dos_header->e_ip);
    printf("e_cs : 0x%X\n", dos_header->e_cs);
    printf("e_lfarlc : 0x%X\n", dos_header->e_lfarlc);
    printf("e_ovno : 0x%X\n", dos_header->e_ovno);
    printf("e_res : 0x%X\n", dos_header->e_res);
    printf("e_oemid : 0x%X\n", dos_header->e_oemid);
    printf("e_oeminfo : 0x%X\n", dos_header->e_oeminfo);
    printf("e_res2 : 0x%X\n", dos_header->e_res2);
    printf("e_lfanew : 0x%X\n", dos_header->e_lfanew);


    //NT Header
    PIMAGE_NT_HEADERS nt_header;

    nt_header = ((PIMAGE_NT_HEADERS)((LPBYTE)dos_header + dos_header->e_lfanew));

    printf("\n");
    printf("[+]++++NT Header++++[+]\n");
    printf("\n");
    printf("Signature : 0x%X\n", nt_header->Signature);

    //File Header
    printf("\n");
    printf("[+]++++NT Header -> File Header++++[+]\n");
    printf("\n");
    printf("Machine : 0x%X\n",nt_header->FileHeader.Machine);
    printf("NumberOfSections : 0x%X\n",nt_header->FileHeader.NumberOfSections);
    printf("TimeDateStamp : 0x%X\n",nt_header->FileHeader.TimeDateStamp);
    printf("PointerToSymbolTable : 0x%X\n",nt_header->FileHeader.PointerToSymbolTable);
    printf("NumberOfSymbols : 0x%X\n",nt_header->FileHeader.NumberOfSymbols);
    printf("SizeOfOptionalHeader : 0x%X\n",nt_header->FileHeader.SizeOfOptionalHeader);
    printf("Characteristics : 0x%X\n",nt_header->FileHeader.Characteristics);


    //Optional Header
    printf("\n");
    printf("[+]++++NT Header -> Optional Header++++[+]\n");
    printf("\n");
    printf("Magic : 0x%X\n", nt_header->OptionalHeader.Magic);
	printf("Major Linker Version : 0x%X\n", nt_header->OptionalHeader.MajorLinkerVersion);
	printf("Minor Linker Version : 0x%X\n", nt_header->OptionalHeader.MinorLinkerVersion);
	printf("Size Of Code : 0x%X\n", nt_header->OptionalHeader.SizeOfCode);
    printf("Size Of Initialized Data : 0x%X\n", nt_header->OptionalHeader.SizeOfInitializedData);
    printf("Size Of UnInitialized Data : 0x%X\n", nt_header->OptionalHeader.SizeOfUninitializedData);
	printf("Address Of Entry Point (.text) : 0x%X\n", nt_header->OptionalHeader.AddressOfEntryPoint);
	printf("Base Of Code : 0x%X\n", nt_header->OptionalHeader.BaseOfCode);
	printf("Image Base : 0x%X\n", nt_header->OptionalHeader.ImageBase);
	printf("Section Alignment : 0x%X\n", nt_header->OptionalHeader.SectionAlignment);
	printf("File Alignment : 0x%X\n", nt_header->OptionalHeader.FileAlignment);
	printf("Major Operating System Version : 0x%X\n", nt_header->OptionalHeader.MajorOperatingSystemVersion);
	printf("Minor Operating System Version : 0x%X\n", nt_header->OptionalHeader.MinorOperatingSystemVersion);
	printf("Major Image Version : 0x%X\n", nt_header->OptionalHeader.MajorImageVersion);
	printf("Minor Image Version : 0x%X\n", nt_header->OptionalHeader.MinorImageVersion);
	printf("Major Subsystem Version : 0x%X\n", nt_header->OptionalHeader.MajorSubsystemVersion);
	printf("Minor Subsystem Version : 0x%X\n", nt_header->OptionalHeader.MinorSubsystemVersion);
	printf("Win32 Version Value : 0x%X\n", nt_header->OptionalHeader.Win32VersionValue);
	printf("Size Of Image : 0x%X\n", nt_header->OptionalHeader.SizeOfImage);
	printf("Size Of Headers : 0x%X\n", nt_header->OptionalHeader.SizeOfHeaders);
	printf("CheckSum : 0x%X\n", nt_header->OptionalHeader.CheckSum);
	printf("Subsystem : 0x%X\n", nt_header->OptionalHeader.Subsystem);
	printf("DllCharacteristics : 0x%X\n", nt_header->OptionalHeader.DllCharacteristics);
	printf("Size Of Stack Reserve : 0x%X\n", nt_header->OptionalHeader.SizeOfStackReserve);
	printf("Size Of Stack Commit : 0x%X\n", nt_header->OptionalHeader.SizeOfStackCommit);
	printf("Size Of Heap Reserve : 0x%X\n", nt_header->OptionalHeader.SizeOfHeapReserve);
	printf("Size Of Heap Commit : 0x%X\n", nt_header->OptionalHeader.SizeOfHeapCommit);
	printf("Loader Flags : 0x%X\n", nt_header->OptionalHeader.LoaderFlags);
	printf("Number Of Rva And Sizes : 0x%X\n", nt_header->OptionalHeader.NumberOfRvaAndSizes);

    //Data Directory
    printf("\n");
    printf("NT Header -> Optional Header -> DataDirectory\n");
    printf("\n");
    printf("[+]++++Export Directory++++[+]\n");
    printf("\n");
    printf("Export Directory RVA : %X\n", nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    printf("Export Directory Size : %X\n", nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

    // printf("Export Directory RVA : %X\n", nt_header->OptionalHeader.DataDirectory[0].VirtualAddress);
    // printf("Export Directory Size : %X\n", nt_header->OptionalHeader.DataDirectory[1].Size);
    printf("\n");
    printf("[+]++++Import Directory++++[+]\n");
    printf("\n");
    printf("Import Directory RVA : %X\n", nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printf("Import Directory Size : %X\n", nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    //Section Header


    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
    printf("\n");
    printf("[+]++++Section Header++++[+]\n");
    printf("\n");
    //printf("T: %s\n", section_header->Name);

    for(int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section_header++){
        
        printf("\n");
        printf("[+]+++++++Section+++++++[+]\n");
        printf("\n");
        printf("Section Name : %s\n", section_header->Name);
        printf("Virtual Size : %x\n", section_header->Misc);
        printf("VirtualAddress : %x\n", section_header->VirtualAddress);
        printf("Raw Size : %x\n", section_header->SizeOfRawData);
        printf("Raw Address : %x\n", section_header->PointerToRawData);
        printf("Reloc Address : %x\n", section_header->PointerToRelocations);
        printf("Line Number : %x\n", section_header->PointerToLinenumbers);
        printf("Relocation Number : %x\n", section_header->NumberOfRelocations);
        printf("Linenumbers Number : %x\n", section_header->NumberOfLinenumbers);
        printf("Characteristics : %x\n", section_header->Characteristics);
        printf("\n");
        
    }

    //Export Directory

    //Name : name of dll
    //Base : first ordinal number 
    //addressoffunction : export address table
    //addressofnames : pointer to name
    //addressofnameordinals : array of indexex to EAT
    //AddressOfFunctions

    printf("\n");
    printf("[+]++++Exported Function++++[+]\n");
    printf("\n");
    getchar();

    PIMAGE_EXPORT_DIRECTORY export = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hKernel32 + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	
	DWORD *exportName = (DWORD*)((LPBYTE)hKernel32 + export->AddressOfNames);

    //Virtual Address = PImageBase + RVA of AddressofFunction

    DWORD  i  = 0;
    for(i; i < export->NumberOfNames; i++){
        printf("[+]%s\n", (ULONG_PTR)hKernel32 + exportName[i]);
    }

    //Export symbols

    printf("\n");
    printf("[+]++++Exported Symbols++++[+]\n");
    printf("\n");
    getchar();

    DWORD *exportFunction = (DWORD*)((LPBYTE)hKernel32 + export->AddressOfFunctions);
    DWORD j = 0;
    for (j; j < export->NumberOfFunctions; j++){
        printf("[+]%p\n", (ULONG_PTR)hKernel32  + exportFunction[j]);
    }

    //export
    //Function name  - Function name pointers

    printf("\n");
    printf("[+]++++Function Name - Function Name Pointers++++[+]\n");
    printf("\n");
    getchar();
    
    DWORD z = 0;

    for (z; z < export->NumberOfFunctions; z++){
        printf("[+]%s -> %p\n", (ULONG_PTR)hKernel32  + exportName[z], (ULONG_PTR)hKernel32  + exportFunction[z]);
    }
   
    //close the handle
    CloseHandle(hKernel32);



    return 0;
}