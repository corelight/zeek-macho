%include macho-file-headers.pac

# The base record for a MACHO file
type MACHO_File = case $context.connection.is_done() of {
    false -> MACHO      : MACHO_Image;
    true  -> overlay    : bytestring &length=1 &transient;
};

type MACHO_Image = record {
    headers : Headers;
};

refine connection MockConnection += {

    %member{
        bool done_;
    %}

    %init{
        done_ = false;
    %}

    function mark_done(): bool
        %{
        done_ = true;
        return true;
        %}

    function is_done(): bool
        %{
        return done_;
        %}
};
