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

    function proc_macho_header(h: MACHO_Header): bool
        %{

        if ( file_macho_header_raw )
            {

            RecordVal* dh = new RecordVal(BifType::Record::Zeek::MACHOHeaderRaw);
            dh->Assign(0, new StringVal(${h.signature}.length(), (const char*) ${h.signature}.data()));
            dh->Assign(1, new StringVal(${h.data}.length(), (const char*) ${h.data}.data()));

            BifEvent::generate_file_macho_header_raw((analyzer::Analyzer *) connection()->bro_analyzer(),
                                                     connection()->bro_analyzer()->GetFile()->GetVal()->Ref(),
                                                     dh);
            }

        return true;
        %}
};

refine typeattr MACHO_Header += &let {
    proc : bool = $context.flow.proc_macho_header(this);
};