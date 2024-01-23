%extern{
    #include "events.bif.h"
%}

analyzer ELF withcontext {
    connection: MockConnection;
    flow:       File;
};

connection MockConnection(bro_analyzer: zeek::file_analysis::Analyzer) {
    upflow = File;
    downflow = File;
};

%include elf-file.pac

flow File {
    flowunit = ELF_File withcontext(connection, this);
}
 
%include elf-analyzer.pac
