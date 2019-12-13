# @TEST-EXEC: zeek -C -r $TRACES/all_executables.pcap %INPUT >elf.out
# @TEST-EXEC: btest-diff elf.out
# @TEST-EXEC: btest-diff elf.log
# @TEST-EXEC: btest-diff files.log

@load Zeek/ELF

event file_elf(f: fa_file)
    {
    print "ELF";
    }

event file_elf_header(f: fa_file, h: Zeek::ELFHeader)
    {
    print "ELF HEADER";
    print h;
    }