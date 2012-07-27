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

# my $global_iter;

# openssl  genrsa  -out /Users/twl/.ssh/to_private.pem  1024
# openssl rsa -in /Users/twl/.ssh/to_private.pem -pubout -out  /Users/twl/to_public.pem

my $private_key = "";
my $public_key_str = ""; 

main:
{
    my $qq = new CGI; 
    my %ch = $qq->Vars();
    
    my %cf = app_config();

    $private_key = $cf{private_key};
    $public_key = `cat $cf{public_key}`;
    chomp($public_key);

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

    mktmp($enc, "/tmp/decodeme.base64");
    `openssl enc -base64 -d -in /tmp/decodeme.base64 -out /tmp/decodeme.dat`;

    $enc = `cat /tmp/decodeme.dat`;
    chomp($enc);
    
    mktmp($enc, "/tmp/tmp.enc");
    mktmp($key, "/tmp/time_order.pub");
    `openssl rsautl -verify -inkey /tmp/time_order.pub -pubin -in /tmp/tmp.enc -out /tmp/decrypted.txt`;
   # print `cat /tmp/decrypted.txt`;
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

    # -o return match, -P Perl extended

    `shasum /tmp/msg.txt | grep -oP '^\\w+' > /tmp/hash.txt`;
    # die "openssl rsautl -sign -inkey $private_key -in /tmp/hash.txt -out /tmp/file.enc 2>&1";
    `openssl rsautl -sign -inkey $private_key -in /tmp/hash.txt -out /tmp/file.enc 2>&1`;
    `openssl enc -base64 -in /tmp/file.enc -out /tmp/file.enc.base64 2>&1`;
    my $var = `cat /tmp/file.enc.base64`;
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

    mktmp($enc, "/tmp/decodeme.base64");

    # Take a base64 string and decode it back to normal data, binary.

    `openssl enc -base64 -d -in /tmp/decodeme.base64 -out /tmp/decodeme.dat`;
    
    if ($?)
    {
        $err = "error: opensssl base64 encode fails\n";
        return $err;
    }

    $enc = `cat /tmp/decodeme.dat`;
    chomp($enc);
    
    mktmp($enc, "/tmp/tmp.enc");
    mktmp($key, "/tmp/time_order.pub");
    `openssl rsautl -verify -inkey /tmp/time_order.pub -pubin -in /tmp/tmp.enc -out /tmp/decrypted.txt`;

    if ($?)
    {
        $err = "error: openssl rsautl verify fails\n";
        return $err;
    }

    return `cat /tmp/decrypted.txt`;
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


