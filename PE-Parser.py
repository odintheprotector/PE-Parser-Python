import pefile

def print_dos_header(dos_header):
    print("******* IMAGE DOS HEADER *******")
    print(f"\t\t{dos_header.e_magic:04X}\t\tMagic Number")
    print(f"\t\t{dos_header.e_cblp:04X}\t\tBytes on last page of file")
    print(f"\t\t{dos_header.e_cp:04X}\t\tPages in file")
    print(f"\t\t{dos_header.e_crlc:04X}\t\tRelocations")
    print(f"\t\t{dos_header.e_cparhdr:04X}\t\tSize of header in paragraphs")
    print(f"\t\t{dos_header.e_minalloc:04X}\t\tMinimum extra paragraphs needed")
    print(f"\t\t{dos_header.e_maxalloc:04X}\t\tMaximum extra paragraphs needed")
    print(f"\t\t{dos_header.e_ss:04X}\t\tInitial (relative) SS value")
    print(f"\t\t{dos_header.e_sp:04X}\t\tInitial SP value")
    print(f"\t\t{dos_header.e_csum:04X}\t\tChecksum")
    print(f"\t\t{dos_header.e_ip:04X}\t\tInitial IP value")
    print(f"\t\t{dos_header.e_cs:04X}\t\tInitial (relative) CS value")
    print(f"\t\t{dos_header.e_lfarlc:04X}\t\tFile address of relocation table")
    print(f"\t\t{dos_header.e_ovno:04X}\t\tOverlay number")
    print(f"\t\t{dos_header.e_oemid:04X}\t\tOEM identifier (for e_oeminfo)")
    print(f"\t\t{dos_header.e_oeminfo:04X}\t\tOEM information; e_oemid specific")
    print(f"\t\t{dos_header.e_lfanew:04X}\t\tFile address of new exe header")

def print_nt_signature(pe):
    print("\n******* NT HEADER *******")
    signature = pe.NT_HEADERS.Signature
    if signature == 0x5A4D:
        print("\t\tMZ\t\tSignature")
    elif signature == 0x454E:
        print("\t\tNE\t\tSignature")
    elif signature == 0x4C45:
        print("\t\tLE\t\tSignature")
    elif signature == 0x00000050:
        print("\t\tPE00\t\tSignature")
    else:
        print("\t\tUNKNOWN\t\tSignature")

def print_file_header(pe):
    print("\n******* FILE HEADER *******")
    machine = pe.FILE_HEADER.Machine
    machine_dict = {
        0x8664: "x64",
        0x014C: "x86",
        0x0200: "ARM",
        0x04C0: "MIPS"
    }
    print(f"\t\t{machine_dict.get(machine, 'UNKNOWN')}\t\tMachine")
    print(f"\t\t{pe.FILE_HEADER.NumberOfSections:04X}\t\tNumber of Sections")
    print(f"\t\t{pe.FILE_HEADER.TimeDateStamp:04X}\tTimestamp")
    print(f"\t\t{pe.FILE_HEADER.PointerToSymbolTable:04X}\tPointer to symbol table")
    print(f"\t\t{pe.FILE_HEADER.NumberOfSymbols:04X}\tNumber of symbols")
    print(f"\t\t{pe.FILE_HEADER.SizeOfOptionalHeader:04X}\tSize of optional header")
    print(f"\t\t{pe.FILE_HEADER.Characteristics:04X}\tCharacteristics")

def print_optional_header(pe):
    print("\n******* OPTIONAL HEADER *******")
    print(f"\t\t{pe.OPTIONAL_HEADER.Magic:04X}\t\tMagic")
    print(f"\t\t{pe.OPTIONAL_HEADER.MajorLinkerVersion:04X}\tMajor Linker Version")
    print(f"\t\t{pe.OPTIONAL_HEADER.MinorLinkerVersion:04X}\tMinor Linker Version")
    print(f"\t\t{pe.OPTIONAL_HEADER.SizeOfCode:04X}\tSize of code")
    print(f"\t\t{pe.OPTIONAL_HEADER.SizeOfInitializedData:04X}\tSize of initialized data")
    print(f"\t\t{pe.OPTIONAL_HEADER.SizeOfUninitializedData:04X}\tSize of uninitialized data")
    print(f"\t\t{pe.OPTIONAL_HEADER.AddressOfEntryPoint:04X}\tAddress of entry point")
    print(f"\t\t{pe.OPTIONAL_HEADER.BaseOfCode:04X}\tBase of Code")
    print(f"\t\t{pe.OPTIONAL_HEADER.ImageBase:08X}\tImage Base")
    print(f"\t\t{pe.OPTIONAL_HEADER.SectionAlignment:04X}\tSection Alignment")
    print(f"\t\t{pe.OPTIONAL_HEADER.FileAlignment:04X}\tFile Alignment")
    print(f"\t\t{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion:04X}\tMajor Operating System Version")
    print(f"\t\t{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion:04X}\tMinor Operating System Version")

def print_section_header(pe):
    print("\n******* SECTION HEADERS *******")
    for section in pe.sections:
        print(f"\t{section.Name.decode().strip()}")
        print(f"\t\t{section.Misc_VirtualSize:04X}\t\tVirtualSize")
        print(f"\t\t{section.VirtualAddress:04X}\t\tVirtualAddress")
        print(f"\t\t{section.SizeOfRawData:04X}\t\tSizeOfRawData")
        print(f"\t\t{section.PointerToRawData:04X}\t\tPointerToRawData")
        print(f"\t\t{section.PointerToRelocations:04X}\t\tPointerToRelocations")
        print(f"\t\t{section.PointerToLinenumbers:04X}\t\tPointerToLinenumbers")
        print(f"\t\t{section.NumberOfRelocations:04X}\t\tNumberOfRelocations")
        print(f"\t\t{section.NumberOfLinenumbers:04X}\t\tNumberOfLinenumbers")
        print(f"\t\t{section.Characteristics:04X}\tCharacteristics")
        print("-------------------------------------------------------------")

def print_import_address_table(pe):
    print("\n******* IMPORT ADDRESS TABLE *******")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"\t{entry.dll.decode()}")
        for imp in entry.imports:
            print(f"\t\t{imp.name.decode() if imp.name else 'Ordinal'}\tAddress: {imp.address if imp.address else 'N/A'}")

def main():
    file_name = input("Enter file name: ")
    try:
        pe = pefile.PE(file_name)
    except Exception as e:
        print(f"Error opening file: {e}")
        return
    print_dos_header(pe.DOS_HEADER)
    print_nt_signature(pe)
    print_file_header(pe)
    print_optional_header(pe)
    print_section_header(pe)
    print_import_address_table(pe)
    
if __name__ == "__main__":
    main()
