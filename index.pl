#!/opt/local/bin/perl

# /usr/bin/perl

use strict;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use DBI;
use HTML::Template;
use HTML::FillInForm;
use session_lib;
use Data::Dumper;

my $global_iter;

# openssl  genrsa  -out /Users/twl/.ssh/to_private.pem  1024
# openssl rsa -in /Users/twl/.ssh/to_private.pem -pubout -out  /Users/twl/to_public.pem

my $private_key = "/Users/twl/.ssh/to_private.pem";
my $public_key = `cat /Users/twl/.ssh/to_public.pem`;
chomp($public_key);


main:
{
    my $qq = new CGI; 
    my %ch = $qq->Vars();
    
    my $template_text = process_template("index.html");
    my $template = HTML::Template->new(scalarref => \$template_text,
                                       die_on_bad_params => 0);

    if (! $ch{state})
    {
        $template->param(show_output => "none");
        $template->param(show_input => "block");
        # $template->param(recs => \@records);
        # $template->param(%cf);
        # $template->param(%ENV);

        # If you wanted to fill in HTML form fields, you'd call
        # HTML::FillInForm on $output below. The usual reason for doing
        # this would be to carry state information (values) between
        # invocations of CGI scripts.
    }
    elsif ($ch{state} eq 'encode')
    {
        my $uhc = send_response("provide_order", $ch{signed}, $ch{checksum_type}, $ch{pub_key});
        
        $template->param(uhc => $uhc);
        $template->param(show_output => "block");
        $template->param(show_input => "none");
    }

    my $output =  $template->output;

    print "Content-Type: text/html; charset=iso-8859-1\n\n$output";
}

# sub request_error
# sub extract_id
# sub extract_pub
# sub verify
# sub secure_checksum

sub encode
{
    my $msg = $_[0];
    mktmp($msg, "/tmp/msg.txt") || die "mktmp fails\n";

    `openssl rsautl -sign -inkey $private_key -in /tmp/msg.txt -out /tmp/file.enc 2>&1`;
    `openssl enc -base64 -in /tmp/file.enc -out /tmp/file.enc.base64 2>&1`;
    my $var = `cat /tmp/file.enc.base64`;
    chomp($var);
    return $var;
}

sub mktmp
{
    my $msg = $_[0];
    my $fn = $_[1];
    open(OUT, ">", $fn);
    print OUT $msg;
    close(OUT);
}




sub listen
{
    # daemons use this
}

sub decode_request
{
    return ("provide_order", @ARGV);

    # if (/(<signed checksum>) (<checksum type>) (<public key>)/ 
    #     return ("provide_order",$1, $2, $3);
    # if /(<order message>) (<my pubic key>) (<digital source of original
    #                                         signature>) (<new checksum type>)/ return ("update_order", $1-4);
    # return ("request_error" $arg)
}


sub send_response
{
    # &{ shift } (@_);
    my $request_type = $_[0];
    my @args = @_[1..3];
    no strict;
    return &$request_type(@args);
}

sub provide_order
{
    my $id = $global_iter++;
    my ($check, $type, $your_pub) = @_;
    return &encode("$check $type $your_pub $id") . " $public_key";
}

sub reprovide_order
{
    my ($message, $source, $type) = @_;
    my $check = checksum($type, $source);
    my $id = extract_id($message);
    my $your_pub = extract_pub($message);
    return encode("$check $type $your_pub $id") . " $public_key";
}

sub update_order
{
    # my ($message, $pub, $source, $type) = @arg;
    # if ($pub == $public_key) && verify($message, $source) &&
    #     secure_checksum($type) then reprovide_order($message, $source, $type)
}


