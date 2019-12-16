%extern{
#include "Event.h"
#include "file_analysis/File.h"
#include "file_analysis/Manager.h"
#include "events.bif.h"
#include "types.bif.h"
%}

%header{
%}

%code{
%}


refine flow File += {

	function proc_elf_header(h: ELF_Header): bool
		%{

		if ( file_elf_header )
			{

			RecordVal* dh = new RecordVal(BifType::Record::Zeek::ELFHeader);
			dh->Assign(0, val_mgr->GetCount(${h.signature}));
			dh->Assign(1, val_mgr->GetCount(${h.cpu_class}));
			dh->Assign(2, val_mgr->GetCount(${h.endianness}));
			dh->Assign(3, val_mgr->GetCount(${h.ver}));
			dh->Assign(4, val_mgr->GetCount(${h.osabi}));
			dh->Assign(5, val_mgr->GetCount(${h.abiversion}));
			dh->Assign(6, new StringVal(${h.unused_1}.length(), (const char*) ${h.unused_1}.data()));
			dh->Assign(7, new StringVal(${h.file_type}.length(), (const char*) ${h.file_type}.data()));
			dh->Assign(8, new StringVal(${h.machine}.length(), (const char*) ${h.machine}.data()));
			dh->Assign(9, new StringVal(${h.version}.length(), (const char*) ${h.version}.data()));
			dh->Assign(10, new StringVal(${h.entry}.length(), (const char*) ${h.entry}.data()));
			dh->Assign(11, new StringVal(${h.phoff}.length(), (const char*) ${h.phoff}.data()));
			dh->Assign(12, new StringVal(${h.shoff}.length(), (const char*) ${h.shoff}.data()));
			dh->Assign(13, new StringVal(${h.flags}.length(), (const char*) ${h.flags}.data()));
			dh->Assign(14, new StringVal(${h.ehsize}.length(), (const char*) ${h.ehsize}.data()));
			dh->Assign(15, new StringVal(${h.phentsize}.length(), (const char*) ${h.phentsize}.data()));
			dh->Assign(16, new StringVal(${h.phnum}.length(), (const char*) ${h.phnum}.data()));
			dh->Assign(17, new StringVal(${h.shentsize}.length(), (const char*) ${h.shentsize}.data()));
			dh->Assign(18, new StringVal(${h.shnum}.length(), (const char*) ${h.shnum}.data()));
			dh->Assign(19, new StringVal(${h.shstrndx}.length(), (const char*) ${h.shstrndx}.data()));
			dh->Assign(20, new StringVal(${h.restofdata}.length(), (const char*) ${h.restofdata}.data()));

			BifEvent::generate_file_elf_header((analyzer::Analyzer *) connection()->bro_analyzer(),
											   connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
											   dh);
			}

		return true;
		%}
};

refine typeattr ELF_Header += &let {
	proc : bool = $context.flow.proc_elf_header(this);
};