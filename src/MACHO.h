#pragma once

#include <string>

#include "Val.h"
//#include "File.h"
//#include "../File.h"
#include "events.bif.h"
#include "types.bif.h"
#include "macho_pac.h"

namespace file_analysis {

/**
 * Analyze MACHO files
 */
class MACHO: public file_analysis::Analyzer {
public:
    ~MACHO();

    static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file)
        { return new MACHO(args, file); }

    virtual bool DeliverStream(const u_char* data, uint64_t len);

    virtual bool EndOfFile();

protected:
    MACHO(RecordVal* args, File* file);
    binpac::MACHO::File* interp;
    binpac::MACHO::MockConnection* conn;
    bool done;
};

} // namespace file_analysis
