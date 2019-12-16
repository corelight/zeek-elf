%include elf-file-headers.pac

# The base record for a ELF file
type ELF_File = case $context.connection.is_done() of {
    false -> ELF	    : ELF_Image;
    true  -> overlay    : bytestring &length=1 &transient;
};

type ELF_Image = record {
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
