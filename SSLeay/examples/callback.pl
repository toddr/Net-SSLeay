#!/usr/local/bin/perl -w
# callback.pl - 8.6.1998, Sampo Kellomaki <sampo@iki.fi>
# Test and demonstrate verify call back
#
# WARNING! Although this code works, it is by no means stable. Expect
# that this stuff may break with newer than 0.9.0. --Sampo

use Socket;
use Net::SSLeay qw(die_now die_if_ssl_error);
Net::SSLeay::load_error_strings();
Net::SSLeay::ERR_load_crypto_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();

($dest_serv, $port, $cert_dir) = @ARGV;      # Read command line

$ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
#Net::SSLeay::CTX_set_default_verify_paths($ctx);
Net::SSLeay::CTX_load_verify_locations($ctx, '', $cert_dir)
    or die_now("CTX load verify loc=`$cert_dir' $!");
Net::SSLeay::CTX_set_verify($ctx, &Net::SSLeay::VERIFY_PEER, \&verify2);
die_if_ssl_error('callback: ctx set verify');

$port = getservbyname  ($port, 'tcp')   unless $port =~ /^\d+$/;
$dest_ip = gethostbyname ($dest_serv);

$dest_serv_params  = pack ('S n a4 x8', &AF_INET, $port, $dest_ip);
socket  (S, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
connect (S, $dest_serv_params)          or die "connect: $!";
select  (S); $| = 1; select (STDOUT);

# The network connection is now open, lets fire up SSL

$ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");
#Net::SSLeay::set_verify ($ssl, &Net::SSLeay::VERIFY_PEER, \&verify);
Net::SSLeay::set_fd($ssl, fileno(S));
print "callback: starting ssl connect...\n";
Net::SSLeay::connect($ssl);
die_if_ssl_error('callback: ssl connect');

print "Cipher `" . Net::SSLeay::get_cipher($ssl) . "'\n";
print Net::SSLeay::dump_peer_certificate($ssl);

Net::SSLeay::ssl_write_all($ssl,"\tcallback ok\n");
shutdown S, 1;
print Net::SSLeay::ssl_read_all($ssl);

Net::SSLeay::free ($ssl);
Net::SSLeay::CTX_free ($ctx);
close S;

print $callback_called ? "OK\n" : "ERROR\n";
exit;

sub verify2 {
    my ($ok, $x509_store_ctx) = @_;
    print "**** Verify 2 called ($ok)\n";
    $callback_called++;
    return 1;
}

sub verify {
    my ($ok, $subj_cert, $issuer_cert, $depth, $err_code, $arg, $cert_chain)
	= @_;
    print "--- Verifying certificate (ok=$ok, depth=$depth, err=$err_code)\n";

    if ($subject_cert) {
	print "Subject certificate:\n";
	    print "  Subject Name: "
		. Net::SSLeay::X509_NAME_oneline(
	            Net::SSLeay::X509_get_subject_name($subject_cert))
		    . "\n";
	    print "  Issuer Name:  "
		. Net::SSLeay::X509_NAME_oneline(
	            Net::SSLeay::X509_get_issuer_name($subject_cert))
		    . "\n";
    }

    if ($issuer_cert) {
	print "Issuer certificate:\n";
	    print "  Subject Name: "
		. Net::SSLeay::X509_NAME_oneline(
	            Net::SSLeay::X509_get_subject_name($subject_cert))
		    . "\n";
	    print "  Issuer Name:  "
		. Net::SSLeay::X509_NAME_oneline(
	            Net::SSLeay::X509_get_issuer_name($subject_cert))
		    . "\n";
    }
    $callback_called++;
    return 1; #$ok; # 1=accept cert, 0=reject
}

__END__
