#include "ELF.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

ELF::ELF(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("ELF"), args, file)
	{
	conn = new binpac::ELF::MockConnection(this);
	interp = new binpac::ELF::File(conn);
	done = false;

    if ( file_elf )
        {
        BifEvent::generate_file_elf((analyzer::Analyzer *) conn->bro_analyzer(),
                                    conn->bro_analyzer()->GetFile()->GetVal()->Ref());
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
