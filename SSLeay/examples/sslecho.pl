#!/usr/local/bin/perl -w
# sslecho.pl - Echo server using SSL
#
# Copyright (c) 1996 Neuronio, Lda. All Rights Reserved.
# Author: Sampo Kellomaki <sampo@iki.fi>
# Date:   27.6.1996
#
# Usage: ./sslecho.pl [*port*]
# E.g.:  ./sslecho.pl 1234

use Socket;
use Net::SSLeay;

$port = shift;
$port = 1234 unless $port;

#
# Look up the numbers from system databases
#

$our_hostname = `hostname`;
chop($our_hostname);
$our_ip = gethostbyname($our_hostname);
$port   = getservbyname ($port, 'tcp') unless $port =~ /^\d+$/;

#
# Create the socket and open a connection
#

$sockaddr_template = 'S n a4 x8';
$our_serv_params = pack ($sockaddr_template, &AF_INET, $port, $our_ip);

socket (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
bind (S, $our_serv_params)             or die "bind:   $!";
listen (S, 5)                          or die "listen: $!";

#
# Prepare SSLeay
#

print "Creating SSL context...\n";
$ctx = Net::SSLeay::CTX_new () or die "CTX_new ($ctx): $!";

while (1) {
    
    print "$$: Accepting connections...\n";
    ($addr = accept (NS, S)) or die "accept: $!";
    $old_out = select (NS); $| = 1; select ($old_out);  # Piping hot!
    
    ($af,$client_port,$client_ip) = unpack($sockaddr_template,$addr);
    @inetaddr = unpack('C4',$client_ip);
    print "$af connection from " . join ('.', @inetaddr) . ":$client_port\n";
    
    #
    # Do SSL negotiation stuff
    #

    print "Creating SSL session (context was '$ctx')...\n";
    $ssl = Net::SSLeay::new($ctx)  or die "new ($ssl): $!";

    print "Setting fd (ctx $ctx, con $ssl)...\n";
    Net::SSLeay::set_fd($ssl, fileno(NS));

    print "Setting private key and certificate...\n";
    
    Net::SSLeay::use_RSAPrivateKey_file ($ssl, 'plain-rsa.pem',
                                         &Net::SSLeay::FILETYPE_PEM)
        or die "use_RSAPrivateKey_file: $!";
    Net::SSLeay::use_certificate_file ($ssl, 'plain-cert.pem',
                                         &Net::SSLeay::FILETYPE_PEM)
        or die "use_certificate_file: $!";

    print "Entering SSL negotiation phase...\n";
    
    $err = Net::SSLeay::accept($ssl);
    Net::SSLeay::print_errs() if $err;
    
    print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";
    
    #
    # Connected. Exchange some data.
    #
    
    $got = Net::SSLeay::read($ssl);
    Net::SSLeay::print_errs();    
    
    print "Got '$got' (" . length ($got) . " chars)\n";
    $got = uc $got;
    
    Net::SSLeay::write ($ssl, $got) or die "write: $!";
    Net::SSLeay::print_errs();    
    
    print "Tearing down the connection.\n";
    
    Net::SSLeay::free ($ssl);
    close NS;
}
Net::SSLeay::CTX_free ($ctx);
close S;

__END__
