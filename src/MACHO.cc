#include "MACHO.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

MACHO::MACHO(RecordVal* args, File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("MACHO"), args, file)
    {
    conn = new binpac::MACHO::MockConnection(this);
    interp = new binpac::MACHO::File(conn);
    done = false;

    if ( file_macho )
        {
        BifEvent::generate_file_macho((analyzer::Analyzer *) conn->bro_analyzer(),
                                      conn->bro_analyzer()->GetFile()->GetVal()->Ref());
        }

    }

MACHO::~MACHO()
    {
    delete interp;
    delete conn;
    }

bool MACHO::DeliverStream(const u_char* data, uint64_t len)
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

bool MACHO::EndOfFile()
    {
    return false;
    }
