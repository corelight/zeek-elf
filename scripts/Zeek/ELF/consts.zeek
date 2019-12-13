module ELF;

export {
	const endian_text: table[count] of string = {
		[1]  				= "Little",
		[2] 				= "Big"
	} &default=function(i: count):string { return fmt("unknown-%d", i); };

	const cpu_class_text: table[count] of string = {
    	[1]  				= "32-bits",
    	[2] 				= "64-bits"
    } &default=function(i: count):string { return fmt("unknown-%d", i); };

	const osabi_text: table[count] of string = {
        [0x00]  				= "System V",
        [0x01]  				= "HP-UX",
        [0x02]  				= "NetBSD",
        [0x03]  				= "Linux",
        [0x04]  				= "GNU Hurd",
        [0x06]  				= "Solaris",
        [0x07]  				= "AIX",
        [0x08]  				= "IRIX",
        [0x09]  				= "FreeBSD",
        [0x0A]  				= "Tru64",
        [0x0B]  				= "Novell Modesto",
        [0x0C]  				= "OpenBSD",
        [0x0D]  				= "OpenVMS",
        [0x0E]  				= "NonStop Kernel",
        [0x0F]  				= "AROS",
        [0x10]  				= "Fenix OS",
        [0x11]  				= "CloudABI"
    } &default=function(i: count):string { return fmt("unknown-%d", i); };

	const filetype_text: table[count] of string = {
        [0x00]  				= "ET_NONE",
        [0x01]  				= "ET_REL",
        [0x02]  				= "ET_EXEC",
        [0x03]  				= "ET_DYN",
        [0x04]  				= "ET_CORE",
        [0xFE00] 				= "ET_LOOS",
        [0xFEFF]  				= "ET_HIOS",
        [0xFF00]  				= "ET_LOPROC",
        [0xFFFF]  				= "ET_HIPROC"
    } &default=function(i: count):string { return fmt("unknown-%d", i); };

	const machine_text: table[count] of string = {
        [0x00]  				= "No specification.",
        [0x02]  				= "SPARC",
        [0x03]  				= "x86",
        [0x08]  				= "MIPS",
        [0x14]  				= "PowerPC",
        [0x16] 					= "S390",
        [0x28]  				= "ARM",
        [0x2A]  				= "SuperH",
        [0x32]  				= "IA-64",
        [0x3E]  				= "x86-64",
        [0xB7]  				= "AArch64",
        [0xF3]  				= "RISC-V",
    } &default=function(i: count):string { return fmt("unknown-%d", i); };
}
