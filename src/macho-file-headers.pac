type Headers = record {
    macho_header     : MACHO_Header;
} &let {
    # Do not care about parsing rest of the file so mark done now ...
    proc:             bool   = $context.connection.mark_done();
};

type MACHO_Header = record {
    signature         : bytestring &length=4;
    # We will assume 5000 bytes are enough to sample
    # but not enough to overwhelm.  This should be tuned.
    data		      : bytestring &length=5000;
};
