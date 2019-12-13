#pragma once

#include <string>

#include "Val.h"
#include "events.bif.h"
#include "types.bif.h"
#include "elf_pac.h"

namespace file_analysis {

/**
 * Analyze ELF files
 */
class ELF: public file_analysis::Analyzer {
public:
	~ELF();

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
		{ return new ELF(args, file); }

	virtual bool DeliverStream(const u_char* data, uint64_t len);

	virtual bool EndOfFile();

protected:
	ELF(RecordVal* args, File* file);
	binpac::ELF::File* interp;
	binpac::ELF::MockConnection* conn;
	bool done;
};

} // namespace file_analysis
