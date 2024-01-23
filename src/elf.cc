#include "elf.h"
#include <zeek/analyzer/Analyzer.h>

using namespace file_analysis;

ELF::ELF(zeek::RecordValPtr args, zeek::file_analysis::File* file)
    : zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("ELF"), args, file)
    {
    conn = new binpac::ELF::MockConnection(this);
    interp = new binpac::ELF::File(conn);
    done = false;

    if ( file_elf )
        {
        zeek::BifEvent::enqueue_file_elf(
                dynamic_cast<zeek::analyzer::Analyzer*>(conn->bro_analyzer()),
                conn->bro_analyzer()->GetFile()->ToVal());
        }

    }

ELF::~ELF()
    {
    delete interp;
    delete conn;
    }

bool ELF::DeliverStream(const u_char* data, uint64_t len)
    {
    if ( conn->is_done() )
        return false;

    try
        {
        interp->NewData(data, data + len);
        }
    catch ( const binpac::Exception& e )
        {
        return false;
        }

    return ! conn->is_done();
    }

bool ELF::EndOfFile()
    {
    return false;
    }
