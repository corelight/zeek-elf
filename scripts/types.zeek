module ELF;
export {
type Zeek::ELFHeader: record {
    # The mach-o signature
	signature               : count;
	cpu_class               : count;
	endianness             	: count;
	ver               		: count;
	osabi               	: count;
	abiversion              : count;
	unused_1               	: string;
	file_type               : string;
	machine               	: string;
	version               	: string;
	entry               	: string;
	phoff               	: string;
	shoff               	: string;
	flags               	: string;
	ehsize               	: string;
	phentsize               : string;
	phnum               	: string;
	shentsize               : string;
	shnum               	: string;
	shstrndx               	: string;
	restofdata              : string;
};
}