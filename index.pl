#!/usr/bin/perl

# #!/opt/local/bin/perl

use strict;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use DBI;
use HTML::Template;
# use HTML::FillInForm;
use session_lib;
use Data::Dumper;

# my $global_iter;

# openssl  genrsa  -out /Users/twl/.ssh/to_private.pem  1024
# openssl rsa -in /Users/twl/.ssh/to_private.pem -pubout -out  /Users/twl/to_public.pem

my $private_key = "";
my $public_key = ""; 
my $fp = "";

main:
{
    my $qq = new CGI; 
    my %ch = $qq->Vars();
    
    # app_config reads the local .app_config which contains only a redirect.
    my %cf = app_config();

    $fp = $cf{file_path};
    $private_key = $cf{private_key};
    $public_key = `cat $cf{public_key}`;
    chomp($public_key);

    my $template_text = process_template("index.html");
    my $template = HTML::Template->new(scalarref => \$template_text,
                                       die_on_bad_params => 1);

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
        # untaint(foo, 1) newline_flag, preserve \s

        my $signed = untaint($ch{signed}, 1);
        my $checksum_type = untaint($ch{checksum_type});
        my $pub_key = untaint($ch{pub_key}, 1);
        
        my $uhc = send_response("provide_order", $signed, $checksum_type, $pub_key);
        
        # Maybe later we'll care if the $uhc says "error: yada yada,
        # but for now just spew it out.

        $template->param(uhc => $uhc);
        $template->param(show_output => "block");
        $template->param(show_input => "none");
    }

    my $output =  $template->output;

    print "Content-Type: text/html; charset=iso-8859-1\n\n$output";
}

sub internal_decode
{
    my $str = $ARGV[0];
    
    $str =~ m/(.*) (-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----.*)/s;
    my $enc = $1;
    my $key = $2;

    mktmp($enc, "$fp/decodeme.base64");
    `openssl enc -base64 -d -in $fp/decodeme.base64 -out $fp/decodeme.dat`;

    $enc = `cat $fp/decodeme.dat`;
    chomp($enc);
    
    mktmp($enc, "$fp/tmp.enc");
    mktmp($key, "$fp/time_order.pub");
    `openssl rsautl -verify -inkey $fp/time_order.pub -pubin -in $fp/tmp.enc -out $fp/decrypted.txt`;
   # print `cat $fp/decrypted.txt`;
}



# sub request_error
# sub extract_id
# sub extract_pub
# sub verify
# sub secure_checksum

sub encode
{
    my $msg = $_[0];
    mktmp($msg, "$fp/msg.txt") || die "mktmp fails\n";

    # -o return match, -P Perl extended

    `shasum $fp/msg.txt | grep -oP '^\\w+' > $fp/hash.txt`;
    # die "openssl rsautl -sign -inkey $private_key -in $fp/hash.txt -out $fp/file.enc 2>&1";
    `openssl rsautl -sign -inkey $private_key -in $fp/hash.txt -out $fp/file.enc 2>&1`;
    `openssl enc -base64 -in $fp/file.enc -out $fp/file.enc.base64 2>&1`;
    my $var = `cat $fp/file.enc.base64`;
    chomp($var);
    return "$msg\n$var";
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


sub send_response
{
    # &{ shift } (@_);
    my $request_type = $_[0];
    my @args = @_[1..3];
    no strict;
    # Only provide_order for now.
    return &$request_type(@args);
}

sub decode
{
    my $enc = $_[0];
    my $key = $_[1];
    my $err = "";

    mktmp($enc, "$fp/decodeme.base64");

    # Take a base64 string and decode it back to normal data, binary.

# oMpMHQ5mNcPrlA9UUYY+LbfSEzQUrEL1hRBWhNzUMuo0J6nT9jJqf3bxFPNMNR8u
# /vo8+OjxvL7kDMcBg63xlYRB/xypmqv7o4wF10YkEQ3RxObS9LYJdv1mBomLRGy/
# Oc0Z3gLAIEfwva8ifrUxymF2RLiq397+TlKF6EVs9vI=


    `openssl enc -base64 -d -in $fp/decodeme.base64 -out $fp/decodeme.dat`;
    
    if ($?)
    {
        $err = "error: opensssl base64 encode fails\n";
        return $err;
    }

    $enc = `cat $fp/decodeme.dat`;
    chomp($enc);
    
    mktmp($enc, "$fp/tmp.enc");
    mktmp($key, "$fp/time_order.pub");
    my $cmd = "openssl rsautl -verify -inkey $fp/time_order.pub -pubin -in $fp/tmp.enc -out $fp/decrypted.txt";
    `$cmd`;

    if ($?)
    {
        $err = "error: openssl rsautl verify fails:\n$cmd\n";
        return $err;
    }

    return `cat $fp/decrypted.txt`;
}


sub ck_type
{
    if ($_[0] =~ m/\b[0-9a-f]{5,40}\b/)
    {
        # http://stackoverflow.com/questions/468370/a-regex-to-match-a-sha1
        return 'sha1';
    }
    elsif ($_[0] =~ m/^\$6\$/)
    {
        # http://www.freebsd.org/doc/en_US.ISO8859-1/books/handbook/crypt.html
        return 'sha256';
    }
    return '';
}

sub next_iter
{
    my $dbh = get_db_handle('uhc.db');
    #die `echo 'insert into uhc_data values (NULL);' | sqlite3 uhc.db`;
    my $sql = "insert into uhc_data  values (null);";
    # my $sql = "select * from uhc_data";
    my $sth = $dbh->prepare($sql);

    if ($dbh->err()) { die "1\n$DBI::errstr\n"; }
    $sth->execute();
    if ($dbh->err()) { die "2\n$DBI::errstr\n"; }
    # die Dumper($sth->fetchrow_hashref());
    commit_handle('uhc.db');

    my $iter = $dbh->last_insert_id('', '', 'uhc_data', '');
    return $iter;
}


sub provide_order
{
    my ($check, $type, $your_pub) = @_;
    chomp($check);
    chomp($your_pub);
    my $id = next_iter();

    my $checksum = decode($check, $your_pub);

    if ($type eq ck_type($checksum))
    {
        return &encode("$check\n$type\n$your_pub\n$id") . "\n$public_key";
    }
    return $checksum;
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


