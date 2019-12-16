type Headers = record {
    elf_header     : ELF_Header;
} &let {
    # Do not care about parsing rest of the file so mark done now ...
    proc:             bool   = $context.connection.mark_done();
};

#
# https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
#
type ELF_Header = record {
    signature         	: uint32;
    cpu_class		  	: uint8;
    endianness		  	: uint8;
    ver					: uint8;
    osabi				: uint8;
    abiversion			: uint8;
    unused_1			: bytestring &length=7;
    file_type			: bytestring &length=2;
    machine				: bytestring &length=2;
    version				: bytestring &length=4;
    entry				: bytestring &length=4*cpu_class;
    phoff				: bytestring &length=4*cpu_class;
    shoff				: bytestring &length=4*cpu_class;
    flags				: bytestring &length=4;
    ehsize				: bytestring &length=2;
    phentsize			: bytestring &length=2;
    phnum				: bytestring &length=2;
    shentsize			: bytestring &length=2;
    shnum				: bytestring &length=2;
    shstrndx			: bytestring &length=2;
    restofdata			: bytestring &length=4935;
} &byteorder=bigendian &length=5000;
