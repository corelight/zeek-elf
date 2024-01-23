%extern{
#include "zeek/Event.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Manager.h"
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

	    auto dh = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::Zeek::ELFHeader);
            dh->Assign(0, zeek::val_mgr->Count(${h.signature}));
            dh->Assign(1, zeek::val_mgr->Count(${h.cpu_class}));
            dh->Assign(2, zeek::val_mgr->Count(${h.endianness}));
            dh->Assign(3, zeek::val_mgr->Count(${h.ver}));
            dh->Assign(4, zeek::val_mgr->Count(${h.osabi}));
            dh->Assign(5, zeek::val_mgr->Count(${h.abiversion}));
            dh->Assign(6, new zeek::StringVal(${h.unused_1}.length(), (const char*) ${h.unused_1}.data()));
            dh->Assign(7, new zeek::StringVal(${h.file_type}.length(), (const char*) ${h.file_type}.data()));
            dh->Assign(8, new zeek::StringVal(${h.machine}.length(), (const char*) ${h.machine}.data()));
            dh->Assign(9, new zeek::StringVal(${h.version}.length(), (const char*) ${h.version}.data()));
            dh->Assign(10, new zeek::StringVal(${h.entry}.length(), (const char*) ${h.entry}.data()));
            dh->Assign(11, new zeek::StringVal(${h.phoff}.length(), (const char*) ${h.phoff}.data()));
            dh->Assign(12, new zeek::StringVal(${h.shoff}.length(), (const char*) ${h.shoff}.data()));
            dh->Assign(13, new zeek::StringVal(${h.flags}.length(), (const char*) ${h.flags}.data()));
            dh->Assign(14, new zeek::StringVal(${h.ehsize}.length(), (const char*) ${h.ehsize}.data()));
            dh->Assign(15, new zeek::StringVal(${h.phentsize}.length(), (const char*) ${h.phentsize}.data()));
            dh->Assign(16, new zeek::StringVal(${h.phnum}.length(), (const char*) ${h.phnum}.data()));
            dh->Assign(17, new zeek::StringVal(${h.shentsize}.length(), (const char*) ${h.shentsize}.data()));
            dh->Assign(18, new zeek::StringVal(${h.shnum}.length(), (const char*) ${h.shnum}.data()));
            dh->Assign(19, new zeek::StringVal(${h.shstrndx}.length(), (const char*) ${h.shstrndx}.data()));
            dh->Assign(20, new zeek::StringVal(${h.restofdata}.length(), (const char*) ${h.restofdata}.data()));

            zeek::BifEvent::enqueue_file_elf_header(
                    dynamic_cast<zeek::analyzer::Analyzer*>(connection()->bro_analyzer()),
                    connection()->bro_analyzer()->GetFile()->ToVal(),
                    dh);
            }

        return true;
        %}
};

refine typeattr ELF_Header += &let {
    proc : bool = $context.flow.proc_elf_header(this);
};
