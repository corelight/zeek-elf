#pragma once

#include <string>

#include "zeek/file_analysis/Analyzer.h"
#include "events.bif.h"
#include "types.bif.h"
#include "elf_pac.h"

namespace file_analysis {

/**
 * Analyze ELF files
 */
class ELF: public zeek::file_analysis::Analyzer {
public:
    ~ELF();

    static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args, zeek::file_analysis::File* file)
        { return new ELF(args, file); }

    virtual bool DeliverStream(const u_char* data, uint64_t len);

    virtual bool EndOfFile();

protected:
    ELF(zeek::RecordValPtr args, zeek::file_analysis::File* file);
    binpac::ELF::File* interp;
    binpac::ELF::MockConnection* conn;
    bool done;
};

} // namespace file_analysis
