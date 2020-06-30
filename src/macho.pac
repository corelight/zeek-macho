%include binpac.pac
%include bro.pac

%extern{
	#include "events.bif.h"
%}

analyzer MACHO withcontext {
	connection: MockConnection;
	flow:       File;
};

connection MockConnection(bro_analyzer: BroFileAnalyzer) {
	upflow = File;
	downflow = File;
};

%include macho-file.pac

flow File {
	flowunit = MACHO_File withcontext(connection, this);
}
 
%include macho-analyzer.pac
