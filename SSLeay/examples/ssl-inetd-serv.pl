#!/usr/local/bin/perl
# ssl-inetd-serv.pl - SSL echo server run from inetd
#
# Copyright (c) 1996 Neuronio, Lda. All Rights Reserved.
# Author: Sampo Kellomaki <sampo@iki.fi>
# Date:   27.6.1996
#
# /etc/inetd.conf
# ssltst  stream  tcp     nowait  root    /usr/users/sampo/perl5.002/ext/Net/SSLeay/examples/ssl-inetd-serv.pl ssl-inetd-serv.pl
#
# /etc/services
# ssltst		1234/tcp
#

use Net::SSLeay;

chdir '/usr/users/sampo/perl5.002/ext/Net/SSLeay/examples' or die "chdir: $!";

$| = 1;  # Piping hot!

open LOG, ">>/dev/console" or die "Can't open log file $!";
select LOG;
print "ssl-inetd-serv.pl started\n";

print "Creating SSL context...\n";
$ctx = Net::SSLeay::CTX_new or die "CTX_new ($ctx) ($!)";

print "Creating SSL con (context was '$ctx')...\n";
$ssl = Net::SSLeay::new($ctx) or die "new ($ssl) ($!)";

print "Setting fds (ctx $ctx, con $ssl)...\n";
Net::SSLeay::set_rfd($ssl, fileno(STDIN));
Net::SSLeay::set_wfd($ssl, fileno(STDOUT));

print "Setting private key and certificate...\n";
    
Net::SSLeay::use_RSAPrivateKey_file ($ssl, 'plain-rsa.pem',
				     &Net::SSLeay::FILETYPE_PEM)
    or die "use_RSAPrivateKey_file: $!";
Net::SSLeay::use_certificate_file ($ssl, 'plain-cert.pem',
				   &Net::SSLeay::FILETYPE_PEM)
    or die "use_certificate_file: $!";
    
print "Entering SSL negotiation phase...\n";
    
Net::SSLeay::accept($ssl) or die "accept: $!";

print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";
    
#
# Connected. Exchange some data.
#

$got = Net::SSLeay::read($ssl);
print "Got '$got' (" . length ($got) . " chars)\n";

$got = uc $got;
print "Sending '$got'\n";

Net::SSLeay::write ($ssl, $got) or die "write: $!";

print "Tearing down the connection.\n";

Net::SSLeay::free ($ssl);
Net::SSLeay::CTX_free ($ctx);

close LOG;

__END__
