module MACHO;
export {
type Zeek::MACHOHeaderRaw: record {
    # The mach-o signature
	signature               : string;
	data                	: string;
};
type Zeek::MACHOFATArch: record {
	cpu_type                : count;
	cpu_subtype             : count;
	offset                	: count;
	size  	                : count;
	align   	            : count;
	reserved   	            : count;
};
type Zeek::MACHOBinaryMeta: record {
	cpu_type                : string;
	cpu_subtype             : string;
	filetype                : string;
	ncmds                   : string;
	sizeofcmds              : string;
	flags                	: string;
	data                	: string;
};
type Zeek::MACHOCommand: record {
	cmd               		: count;
	cmdsize                	: count;
	segname             	: string;
	vmaddr                	: count;
	vmsize                  : count;
	fileoff              	: count;
	filesize                : count;
	maxprot                	: count;
	initprot                : count;
	nsects                	: count;
	flags                	: count;
};
type Zeek::MACHOCommandData: record {
	cmd               		: count;
	cmdsize                	: count;
	data 	            	: string;
};
}