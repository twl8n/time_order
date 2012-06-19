#!/usr/bin/perl

use strict;

my $global_iter;

# openssl  genrsa  -out /Users/twl/.ssh/to_private.pem  1024
# openssl rsa -in /Users/twl/.ssh/to_private.pem -pubout -out  /Users/twl/to_public.pem

my $private_key = "%ENV{HOME}/.ssh/to_private.pem";
my $public_key = `cat $HOME/.ssh/to_public.pem`;
chomp($public_key);

# sub request_error
# sub extract_id
# sub extract_pub
# sub verify
# sub secure_checksum

sub encode
{
    my $msg = $_[0];
    mktmp($msg, "/tmp/msg.txt");

    system("openssl rsautl -sign -inkey $private_key -in /tmp/msg.txt -out /tmp/file.enc");
    `openssl enc -base64 -in /tmp/file.enc -out /tmp/file.enc.base64`;
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

main:
{

    send_response(decode_request());
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
    &$request_type(@args);
}

sub provide_order
{
    my $id = $global_iter++;
    my ($check, $type, $your_pub) = @_;
    print &encode("$check $type $your_pub $id") . " $public_key";
}

sub reprovide_order
{
    my ($message, $source, $type) = @_;
    my $check = checksum($type, $source);
    my $id = extract_id($message);
    my $your_pub = extract_pub($message);
    print encode("$check $type $your_pub $id") . " $public_key";
}

sub update_order
{
    # my ($message, $pub, $source, $type) = @arg;
    # if ($pub == $public_key) && verify($message, $source) &&
    #     secure_checksum($type) then reprovide_order($message, $source, $type)
}


