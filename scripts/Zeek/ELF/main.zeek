module ELF;

@load ./consts

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Current timestamp.
		ts:                  time              	&log;
		## File id of this portable executable file.
		id:                  string            	&log;
		signature:			 count			   	&log &optional;
		cpu_class: 			 string				&log &optional;
		endianness: 		 string				&log &optional;
		ver: 				 count				&log &optional;
		osabi: 				 string			    &log &optional;
		abiversion: 		 count			    &log &optional;
		unused_1:  			 string 			&log &optional;
		file_type: 			 string				&log &optional;
		machine: 			 string				&log &optional;
		version: 			 count				&log &optional;
		entry: 				 count				&log &optional;
		phoff: 				 count				&log &optional;
		shoff: 				 count				&log &optional;
		flags: 				 count				&log &optional;
		ehsize: 			 count				&log &optional;
		phentsize: 			 count				&log &optional;
		phnum: 				 count				&log &optional;
		shentsize: 			 count				&log &optional;
		shnum: 				 count				&log &optional;
		shstrndx: 			 count				&log &optional;
		};

	## Event for accessing logged records.
	global log_elf: event(rec: Info);

	## A hook that gets called when we first see an ELF file.
	global set_file: hook(f: fa_file);
}

redef record fa_file += {
	elf: Info &optional;
};

const elf_mime_types = { "application/x-executable", "application/x-coredump",
						 "application/x-sharedlib", "application/x-object"};

event zeek_init() &priority=5
	{
	Files::register_for_mime_types(Files::ANALYZER_ELF, elf_mime_types);
	Log::create_stream(LOG, [$columns=Info, $ev=log_elf, $path="elf"]);
	}

hook set_file(f: fa_file) &priority=5
	{
	if ( ! f?$elf )
	    {
		f$elf = [$ts=network_time(), $id=f$id];
	    }
    }

event file_elf(f: fa_file) &priority=5
	{
	hook set_file(f);
	}

event file_elf_header(f: fa_file, h: Zeek::ELFHeader) &priority=5
	{
	hook set_file(f);

	local is_LE: bool = (h$endianness == 1 ? T : F);

	f$elf$signature = h$signature;
	f$elf$cpu_class = cpu_class_text[h$cpu_class];
	f$elf$endianness = endian_text[h$endianness];
	f$elf$ver = h$ver;
	f$elf$osabi = osabi_text[h$osabi];
	f$elf$abiversion = h$abiversion;
	f$elf$unused_1 = h$unused_1;

	# From here we must watch byte order
	f$elf$file_type = filetype_text[bytestring_to_count(h$file_type, is_LE)];
	f$elf$machine = machine_text[bytestring_to_count(h$machine, is_LE)];
	f$elf$version = bytestring_to_count(h$version, is_LE);
	f$elf$entry = bytestring_to_count(h$entry, is_LE);
	f$elf$phoff = bytestring_to_count(h$phoff, is_LE);
	f$elf$shoff = bytestring_to_count(h$shoff, is_LE);
	f$elf$flags = bytestring_to_count(h$flags, is_LE);
	f$elf$ehsize = bytestring_to_count(h$ehsize, is_LE);
	f$elf$phentsize = bytestring_to_count(h$phentsize, is_LE);
	f$elf$phnum = bytestring_to_count(h$phnum, is_LE);
	f$elf$shentsize = bytestring_to_count(h$shentsize, is_LE);
	f$elf$shnum = bytestring_to_count(h$shnum, is_LE);
	f$elf$shstrndx = bytestring_to_count(h$shstrndx, is_LE);
	}

event file_state_remove(f: fa_file) &priority=-5
	{
	if ( f?$elf )
	    {
		Log::write(LOG, f$elf);
		}
	}