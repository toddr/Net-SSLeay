# SSLeay.pm - Perl module for using Eric Young's implementation of SSL
#
# Copyright (c) 1996 Sampo Kellomaki <sampo@iki.fi>
# All Rights Reserved.
#
# The distribution and use of this module are subject to the conditions
# listed in COPYRIGHT file at the root of Eric Young's SSLeay-0.6.0
# distribution (i.e. free, but mandatory attribution and NO WARRANTY).

package Net::SSLeay;

$trace = 3;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);
use Socket;

require Exporter;
require DynaLoader;
require AutoLoader;

$VERSION = '0.04';
@ISA = qw(Exporter DynaLoader);
@EXPORT_OK = qw(
	AT_MD5_WITH_RSA_ENCRYPTION
	CB_ACCEPT_EXIT
	CB_ACCEPT_LOOP
	CB_CONNECT_EXIT
	CB_CONNECT_LOOP
	CK_DES_192_EDE3_CBC_WITH_MD5
	CK_DES_192_EDE3_CBC_WITH_SHA
	CK_DES_64_CBC_WITH_MD5
	CK_DES_64_CBC_WITH_SHA
	CK_DES_64_CFB64_WITH_MD5_1
	CK_IDEA_128_CBC_WITH_MD5
	CK_NULL
	CK_NULL_WITH_MD5
	CK_RC2_128_CBC_EXPORT40_WITH_MD5
	CK_RC2_128_CBC_WITH_MD5
	CK_RC4_128_EXPORT40_WITH_MD5
	CK_RC4_128_WITH_MD5
	CLIENT_VERSION
	CT_X509_CERTIFICATE
	FILETYPE_ASN1
	FILETYPE_PEM
	F_CLIENT_CERTIFICATE
	F_CLIENT_HELLO
	F_CLIENT_MASTER_KEY
	F_D2I_SSL_SESSION
	F_GET_CLIENT_FINISHED
	F_GET_CLIENT_HELLO
	F_GET_CLIENT_MASTER_KEY
	F_GET_SERVER_FINISHED
	F_GET_SERVER_HELLO
	F_GET_SERVER_VERIFY
	F_I2D_SSL_SESSION
	F_READ_N
	F_REQUEST_CERTIFICATE
	F_SERVER_HELLO
	F_SSL_ACCEPT
	F_SSL_CERT_NEW
	F_SSL_CONNECT
	F_SSL_ENC_DES_CBC_INIT
	F_SSL_ENC_DES_CFB_INIT
	F_SSL_ENC_DES_EDE3_CBC_INIT
	F_SSL_ENC_IDEA_CBC_INIT
	F_SSL_ENC_NULL_INIT
	F_SSL_ENC_RC2_CBC_INIT
	F_SSL_ENC_RC4_INIT
	F_SSL_GET_NEW_SESSION
	F_SSL_MAKE_CIPHER_LIST
	F_SSL_NEW
	F_SSL_READ
	F_SSL_RSA_PRIVATE_DECRYPT
	F_SSL_RSA_PUBLIC_ENCRYPT
	F_SSL_SESSION_NEW
	F_SSL_SESSION_PRINT_FP
	F_SSL_SET_CERTIFICATE
	F_SSL_SET_FD
	F_SSL_SET_RFD
	F_SSL_SET_WFD
	F_SSL_STARTUP
	F_SSL_USE_CERTIFICATE
	F_SSL_USE_CERTIFICATE_ASN1
	F_SSL_USE_CERTIFICATE_FILE
	F_SSL_USE_PRIVATEKEY
	F_SSL_USE_PRIVATEKEY_ASN1
	F_SSL_USE_PRIVATEKEY_FILE
	F_SSL_USE_RSAPRIVATEKEY
	F_SSL_USE_RSAPRIVATEKEY_ASN1
	F_SSL_USE_RSAPRIVATEKEY_FILE
	F_WRITE_PENDING
	MAX_MASTER_KEY_LENGTH_IN_BITS
	MAX_RECORD_LENGTH_2_BYTE_HEADER
	MAX_RECORD_LENGTH_3_BYTE_HEADER
	MAX_SSL_SESSION_ID_LENGTH_IN_BYTES
	MIN_RSA_MODULUS_LENGTH_IN_BYTES
	MT_CLIENT_CERTIFICATE
	MT_CLIENT_FINISHED
	MT_CLIENT_HELLO
	MT_CLIENT_MASTER_KEY
	MT_ERROR
	MT_REQUEST_CERTIFICATE
	MT_SERVER_FINISHED
	MT_SERVER_HELLO
	MT_SERVER_VERIFY
	NOTHING
	PE_BAD_CERTIFICATE
	PE_NO_CERTIFICATE
	PE_NO_CIPHER
	PE_UNSUPPORTED_CERTIFICATE_TYPE
	READING
	RWERR_BAD_MAC_DECODE
	RWERR_BAD_WRITE_RETRY
	RWERR_INTERNAL_ERROR
	R_BAD_AUTHENTICATION_TYPE
	R_BAD_CHECKSUM
	R_BAD_MAC_DECODE
	R_BAD_RESPONSE_ARGUMENT
	R_BAD_SSL_FILETYPE
	R_BAD_SSL_SESSION_ID_LENGTH
	R_BAD_STATE
	R_BAD_WRITE_RETRY
	R_CHALLENGE_IS_DIFFERENT
	R_CIPHER_CODE_TOO_LONG
	R_CIPHER_TABLE_SRC_ERROR
	R_CONECTION_ID_IS_DIFFERENT
	R_INVALID_CHALLENGE_LENGTH
	R_NO_CERTIFICATE_SET
	R_NO_CERTIFICATE_SPECIFIED
	R_NO_CIPHER_LIST
	R_NO_CIPHER_MATCH
	R_NO_CIPHER_WE_TRUST
	R_NO_PRIVATEKEY
	R_NO_PUBLICKEY
	R_NO_READ_METHOD_SET
	R_NO_WRITE_METHOD_SET
	R_NULL_SSL_CTX
	R_PEER_DID_NOT_RETURN_A_CERTIFICATE
	R_PEER_ERROR
	R_PEER_ERROR_CERTIFICATE
	R_PEER_ERROR_NO_CIPHER
	R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE
	R_PERR_ERROR_NO_CERTIFICATE
	R_PUBLIC_KEY_ENCRYPT_ERROR
	R_PUBLIC_KEY_IS_NOT_RSA
	R_PUBLIC_KEY_NO_RSA
	R_READ_WRONG_PACKET_TYPE
	R_REVERSE_KEY_ARG_LENGTH_IS_WRONG
	R_REVERSE_MASTER_KEY_LENGTH_IS_WRONG
	R_REVERSE_SSL_SESSION_ID_LENGTH_IS_WRONG
	R_SHORT_READ
	R_SSL_SESSION_ID_IS_DIFFERENT
	R_UNABLE_TO_EXTRACT_PUBLIC_KEY
	R_UNDEFINED_INIT_STATE
	R_UNKNOWN_REMOTE_ERROR_TYPE
	R_UNKNOWN_STATE
	R_UNSUPORTED_CIPHER
	R_WRONG_PUBLIC_KEY_TYPE
	R_X509_LIB
	SERVER_VERSION
	SESSION
	SESSION_ASN1_VERSION
	ST_ACCEPT
	ST_BEFORE
	ST_CLIENT_START_ENCRYPTION
	ST_CONNECT
	ST_GET_CLIENT_FINISHED_A
	ST_GET_CLIENT_FINISHED_B
	ST_GET_CLIENT_HELLO_A
	ST_GET_CLIENT_HELLO_B
	ST_GET_CLIENT_MASTER_KEY_A
	ST_GET_CLIENT_MASTER_KEY_B
	ST_GET_SERVER_FINISHED_A
	ST_GET_SERVER_FINISHED_B
	ST_GET_SERVER_HELLO_A
	ST_GET_SERVER_HELLO_B
	ST_GET_SERVER_VERIFY_A
	ST_GET_SERVER_VERIFY_B
	ST_INIT
	ST_OK
	ST_READ_BODY
	ST_READ_HEADER
	ST_SEND_CLIENT_CERTIFICATE_A
	ST_SEND_CLIENT_CERTIFICATE_B
	ST_SEND_CLIENT_CERTIFICATE_C
	ST_SEND_CLIENT_CERTIFICATE_D
	ST_SEND_CLIENT_FINISHED_A
	ST_SEND_CLIENT_FINISHED_B
	ST_SEND_CLIENT_HELLO_A
	ST_SEND_CLIENT_HELLO_B
	ST_SEND_CLIENT_MASTER_KEY_A
	ST_SEND_CLIENT_MASTER_KEY_B
	ST_SEND_REQUEST_CERTIFICATE_A
	ST_SEND_REQUEST_CERTIFICATE_B
	ST_SEND_REQUEST_CERTIFICATE_C
	ST_SEND_REQUEST_CERTIFICATE_D
	ST_SEND_SERVER_FINISHED_A
	ST_SEND_SERVER_FINISHED_B
	ST_SEND_SERVER_HELLO_A
	ST_SEND_SERVER_HELLO_B
	ST_SEND_SERVER_VERIFY_A
	ST_SEND_SERVER_VERIFY_B
	ST_SERVER_START_ENCRYPTION
	ST_X509_GET_CLIENT_CERTIFICATE
	ST_X509_GET_SERVER_CERTIFICATE
	TXT_DES_192_EDE3_CBC_WITH_MD5
	TXT_DES_192_EDE3_CBC_WITH_SHA
	TXT_DES_64_CBC_WITH_MD5
	TXT_DES_64_CBC_WITH_SHA
	TXT_DES_64_CFB64_WITH_MD5_1
	TXT_IDEA_128_CBC_WITH_MD5
	TXT_NULL
	TXT_NULL_WITH_MD5
	TXT_RC2_128_CBC_EXPORT40_WITH_MD5
	TXT_RC2_128_CBC_WITH_MD5
	TXT_RC4_128_EXPORT40_WITH_MD5
	TXT_RC4_128_WITH_MD5
	VERIFY_CLIENT_ONCE
	VERIFY_FAIL_IF_NO_PEER_CERT
	VERIFY_NONE
	VERIFY_PEER
	WRITING
	X509_LOOKUP
	CTX_new
	CTX_free
	new
	free
	debug
	accept
	clear
	connect
	set_fd
	set_rfd
	set_wfd
	get_fd
	read
	write
	use_RSAPrivateKey
	use_RSAPrivateKey_ASN1
	use_RSAPrivateKey_file
	use_PrivateKey
	use_PrivateKey_ASN1
	use_PrivateKey_file
	use_certificate
	use_certificate_ASN1
	use_certificate_file
	load_error_strings
	ERR_load_SSL_strings
	state_string
	rstate_string
	state_string_long
	rstate_string_long
	get_time
	set_time
	get_timeout
	set_timeout
	copy_session_id
	set_read_ahead
	get_read_ahead
	pending
	get_cipher_list
	set_cipher_list
	get_cipher
	get_shared_ciphers
	get_peer_certificate
	set_verify
	flush_sessions
	set_bio
	get_rbio
	get_wbio
	SESSION_new
	SESSION_print
	SESSION_free
	i2d_SSL_SESSION
	set_session
	add_session
	remove_session
	d2i_SSL_SESSION
	BIO_f_ssl
	ERR_get_error
	ERR_error_string
	err
	clear_error
);

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined SSLeay macro $constname";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap Net::SSLeay $VERSION;

# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Documentation. Use `perl-root/pod/pod2html SSLeay.pm` to output html

=head1 NAME

Net::SSLeay - Perl extension for using Eric Young's implementation of SSL

=head1 SYNOPSIS

  use Net::SSLeay;

See ssl.h header from SSLeay C distribution for list of functions to call.
	
SSLeay names are stripped of the initial `SSL_', generally you should
use Net::SSLeay:: in place. For example:
  
In C:

	#include <ssl.h>
	
	err = SSL_set_verify (ssl, SSL_VERIFY_CLIENT_ONCE,
				   &your_call_back_here);
	
In perl:

	use Net::SSLeay;

	$err = Net::SSLeay::set_verify ($ssl,
					&Net::SSLeay::VERIFY_CLIENT_ONCE,
					\&your_call_back_here);

If the function does not start by SSL_ you should use the full
function name, e.g.:

	$err = &Net::SSLeay::ERR_get_error;

Following new functions behave in perlish way:

	$got = Net::SSLeay::read($ssl);
                                    # Performs SSL_read, but returns $got
                                    # resized according to data received.
                                    # Returns undef on failure.

	Net::SSLeay::write($ssl, $foo) || die;
                                    # Performs SSL_write, but automatically
                                    # figures out the size of $foo

	$got = Net::SSLeay::cat($dest_host, $port, $foo);
                                    # Sends $foo and gets response

=head1 DESCRIPTION

Perl glue to call some of the functions in SSLeay library. Note: this module
is still under construction. I'll implement more of SSLeay and associated
libraries once I understand better how to use them. Also documentation
will improve once the SSLeay documentation improves.

Currently much of the stuff that is implemented as C macros is missing.
Interface to supporting libraries is also missing.

This module uses SSLeay-0.6.0, be sure you get it first.

=head2 Sockets

Perl uses filehandles for all I/O. While SSLeay has quite flexible BIO
mechanism, this extension still sticks to using file descriptors. Thus
to attach SSLeay to socket you should use fileno to extract the
underlying file descriptor:

    Net::SSLeay::set_fd($ssl, fileno(S));   # Must use fileno


=head2 Callbacks

At the moment the implementation of verify_callback is crippeled in
the sense that at any given time there can be only one call back which
is shared by all SSLeay contexts, sessions ans connections. This is
due to us having to keep the reference to the perl call back in a
static variable so that the callback C glue can find it. To remove
this restriction would require either a more complex data structure
(like a hash?) in XSUB to map the call backs to their owners or,
cleaner, adding a context pointer in the SSL structure. This context would
then be passed to the C callback, which in our case would be the glue
to look up the proper Perl function from the context and call it.

The verify call back looks like this in C:

	int (*callback)(int ok,X509 *subj_cert,X509 *issuer_cert,
                        int depth,int errorcode)

The corresponding Perl function should be something like this:

	sub verify {
		my ($ok, $subj_cert, $issuer_cert, $depth, $errorcode) = @_;
		print "Verifying certificate...\n";
		...
	}

It is used like this:

	Net::SSLeay::set_verify ($ssl, Net::SSLeay::VERIFY_PEER, \&verify);


No other callbacks are implemented yet.

=head1 EXAMPLES

Following is a simple SSLeay client (with too little error checking :-(

    #!/usr/local/bin/perl
    use Socket;
    use Net::SSLeay;
    
    ($dest_serv, $port, $msg) = @ARGV;      # Read command line
    $port = getservbyname  ($port, 'tcp')   unless $port =~ /^\d+$/;
    $dest_ip = gethostbyname ($dest_serv);
    
    $sockaddr_template = 'S n a4 x8';
    $dest_serv_params  = pack ($sockaddr_template, &AF_INET, $port, $dest_ip);
    
    socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
    connect (S, $dest_serv_params)          or die "connect: $!";
    select  (S); $| = 1; select (STDOUT);
    
    # The network connection is now open, lets fire up SSL    

    $ctx = Net::SSLeay::CTX_new() or die "Failed to create SSL_CTX $!";
    $ssl = Net::SSLeay::new($ctx) or die "Failed to create SSL $!";
    Net::SSLeay::set_fd($ssl, fileno(S));   # Must use fileno
    $res = Net::SSLeay::connect($ssl);
    print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";
    
    # Exchange data
    
    $res = Net::SSLeay::write($ssl, $msg);  # Perl knows how long $msg is
    shutdown S, 1;  # Half close --> No more output, sends EOF to server
    $got = Net::SSLeay::read($ssl);         # Perl returns undef on failure
    print $got;
	    
    Net::SSLeay::free ($ssl);               # Tear down connection
    Net::SSLeay::CTX_free ($ctx);
    close S;

Following is a simple SSLeay echo server (non forking):

    #!/usr/local/bin/perl -w
    use Socket;
    use Net::SSLeay;

    $our_hostname = `hostname`; chop($our_hostname);
    $our_ip = gethostbyname($our_hostname);
    $port = 1235;							 
    $sockaddr_template = 'S n a4 x8';
    $our_serv_params = pack ($sockaddr_template, &AF_INET, $port, $our_ip);

    socket (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
    bind (S, $our_serv_params)             or die "bind:   $!";
    listen (S, 5)                          or die "listen: $!";
    $ctx = Net::SSLeay::CTX_new ()         or die "CTX_new ($ctx): $!";

    while (1) {    
        print "Accepting connections...\n";
        ($addr = accept (NS, S))           or die "accept: $!";
        select (NS); $| = 1; select (STDOUT);  # Piping hot!
    
        ($af,$client_port,$client_ip) = unpack($sockaddr_template,$addr);
        @inetaddr = unpack('C4',$client_ip);
        print "$af connection from " .
	    join ('.', @inetaddr) . ":$client_port\n";
    
	# We now have a network connection, lets fire up SSLeay...

        $ssl = Net::SSLeay::new($ctx)      or die "SSL_new ($ssl): $!";
        Net::SSLeay::set_fd($ssl, fileno(NS));
    
        Net::SSLeay::use_RSAPrivateKey_file ($ssl, 'plain-rsa.pem',
                                             &Net::SSLeay::FILETYPE_PEM);
        Net::SSLeay::use_certificate_file ($ssl, 'plain-cert.pem',
	 				   &Net::SSLeay::FILETYPE_PEM);
        $err = Net::SSLeay::accept($ssl);
        print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";
    
        # Connected. Exchange some data.
    
        $got = Net::SSLeay::read($ssl);     # Returns undef on fail
        print "Got '$got' (" . length ($got) . " chars)\n";
     
        Net::SSLeay::write ($ssl, uc ($got)) or die "write: $!";
    
        Net::SSLeay::free ($ssl);           # Tear down connection
        close NS;
    }

Yet another echo server. This one runs from /etc/inetd.conf so it avoids
all the socket code over head. Only caveat is opening rsa key file -
it had better be without any encryption or else it won't know where
to ask for the password.

    #!/usr/local/bin/perl
    # /etc/inetd.conf
    #    ssltst stream tcp nowait root /path/to/server.pl server.pl
    # /etc/services
    #    ssltst		1234/tcp
    use Net::SSLeay;
    chdir '/key/dir' or die "chdir: $!";
    $| = 1;  # Piping hot!
    open LOG, ">>/dev/console" or die "Can't open log file $!";
    select LOG; print "server.pl started\n";

    
    $ctx = Net::SSLeay::CTX_new()     or die "CTX_new ($ctx) ($!)";
    $ssl = Net::SSLeay::new($ctx)     or die "new ($ssl) ($!)";

    # We get already open network connection from inetd, now we just
    # need to attach SSLeay to STDIN and STDOUT
    Net::SSLeay::set_rfd($ssl, fileno(STDIN));
    Net::SSLeay::set_wfd($ssl, fileno(STDOUT));

    Net::SSLeay::use_RSAPrivateKey_file ($ssl, 'plain-rsa.pem',
				         &Net::SSLeay::FILETYPE_PEM);
    Net::SSLeay::use_certificate_file ($ssl, 'plain-cert.pem',
				       &Net::SSLeay::FILETYPE_PEM);
    Net::SSLeay::accept($ssl) or die "accept: $!";
    print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";
    
    $got = Net::SSLeay::read($ssl);
    print "Got '$got' (" . length ($got) . " chars)\n";

    Net::SSLeay::write ($ssl, uc($got)) or die "write: $!";

    Net::SSLeay::free ($ssl);         # Tear down the connection
    Net::SSLeay::CTX_free ($ctx);
    close LOG;


=head1 AUTHOR

Sampo Kellomaki <sampo@iki.fi>

=head1 COPYRIGHT

Copyright (c) 1996 Sampo Kellomaki <sampo@iki.fi>, All Rights Reserved.

Distribution and use of this module is under the same terms as the
SSLeay package itself (i.e. free, but mandatory attribution; NO
WARRANTY). Please consult COPYRIGHT file in the root of the SSLeay
distribution.

While the source distribution of this perl module does not contain Eric's
code, if you use this module you will use Eric's library. Please give him
credit.

=head1 SEE ALSO

  perl-source-root/ext/Net/SSLeay/examples - Example servers and a client
  doc directory of SSLeay distribution
  <http://www.psy.uq.oz.au/~ftp/Crypto/>   - SSLeay online documentation 
  <ftp://ftp.psy.uq.oz.au/pub/Crypto/SSL>  - current SSLeay source
  <http://www.netscape.com/info/SSL.html>  - SSL Draft specification
  <http://www.neuronio.pt/SSLeay.pm.html/> - SSLeay.pm home

=cut

sub print_errs {
    my ($count, $err) = (0,0);
    while ($err = Net::SSLeay::ERR_get_error()) {
	$count ++;
	print "$count - " . Net::SSLeay::ERR_error_string($err) . "\n";
    }
    return $count;
}

sub cat { # address, port, message --> returns reply
    my ($dest_serv, $port, $out_message) = @_;
    my $chatlog = '';
    my ($old_out, $dest_serv_ip, $sockaddr_template, $dest_serv_params);
    my ($ctx, $ssl, $got);
    
    #
    # Look up the numbers from system databases
    #
    
    $port = getservbyname  ($port, 'tcp') unless $port =~ /^\d+$/;
    $dest_serv_ip = gethostbyname ($dest_serv);
    
    #
    # Create the socket and open a connection
    #
    
    $sockaddr_template = 'S n a4 x8';
    $dest_serv_params  = pack ($sockaddr_template, &AF_INET,
			       $port, $dest_serv_ip);
    
    if (socket (SSLCAT_S, &AF_INET, &SOCK_STREAM, 0)) {
	if (connect (SSLCAT_S, $dest_serv_params)) {
	    
	    $old_out = select (SSLCAT_S); $| = 1; select ($old_out);
	    
	    #
	    # Do SSL negotiation stuff
	    #
	    
	    #print "Creating SSL context...\n";
	    $ctx = Net::SSLeay::CTX_new();
	    Net::SSLeay::print_errs();
	    
	    #print "Creating SSL con (context was '$ctx')...\n";
	    $ssl = Net::SSLeay::new($ctx);
	    Net::SSLeay::print_errs();
	    
	    #print "Setting fd (ctx $ctx, con $ssl)...\n";
	    Net::SSLeay::set_fd($ssl, fileno(SSLCAT_S));
	    Net::SSLeay::print_errs();
	    
	    #print "Entering SSL negotiation phase...\n";
		
	    $got = Net::SSLeay::connect($ssl);
	    #print "SSLeay connect returned $got\n";
	    Net::SSLeay::print_errs();
	    
	    #print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";
	    Net::SSLeay::print_errs();
	    
	    #
	    # Connected. Exchange some data.
	    #
	    
	    #print "sslcat $$: sending '$out_message'...\n";
	    $got = Net::SSLeay::write($ssl, $out_message);
	    #print "write returned $got\n";
	    Net::SSLeay::print_errs();
	    
	    shutdown SSLCAT_S, 1;  # Half close --> No more output
	                           #                sends EOF to server
	    
	    #print "receiving...\n";
	    $got = Net::SSLeay::read($ssl);
	    Net::SSLeay::print_errs();
	    #print "Got '$got' (" . length($got) . " chars)\n";
	    
	  Net::SSLeay::free ($ssl);
          Net::SSLeay::print_errs();
	  Net::SSLeay::CTX_free ($ctx);
          Net::SSLeay::print_errs();
	} else {
	    print "Net::SSLeay::cat $$: Failed to connect to "
		. "$dest_serv ($!).\n";
	}
	close SSLCAT_S;
    } else {
	print "Net::SSLeay::cat $$: Failed to create socket: $!.\n";
    }
    return $got;
}

