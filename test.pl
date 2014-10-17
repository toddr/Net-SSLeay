#!/usr/bin/perl
# 24.6.1998, 8.7.1998, Sampo Kellomaki <sampo@iki.fi>
# 31.7.1999, added more tests --Sampo
# 7.4.2001,  upgraded to OpenSSL-0.9.6a --Sampo
# 25.4.2001, added test for 64 bit pointer cast by aspa --Sampo
# 20.8.2001, moved checking which perl to use higher up. Thanks
#            Gordon Lack <gml4410@ggr.co.uk> --Sampo
# 7.12.2001, added test cases for client certificates and proxy SSL --Sampo
# $Id$
#
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use Config;

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..15\n";}
END {print "not ok 1\n" unless $::loaded;}
select(STDOUT); $|=1;
use Net::SSLeay qw(die_now die_if_ssl_error);
$::loaded = 1;
print "ok 1\n";

######################### End of black magic.

my $trace = $ENV{TEST_TRACE} || 1;  # 0=silent, 1=verbose, 2=debugging
#$Net::SSLeay::trace = 3;

my $mb = 1;     # size of the bulk tests
my $errors = 0;
my $silent = $trace>1 ? '' : '>/dev/null 2>/dev/null';
my ($pid,$redir,$res,$bytes,$secs);

sub test {
    my ($num, $test) = @_;
    $errors++ unless $test;
    return $test ? "ok $num\n" : "*** not ok $num\n\n"
}

my $inc = join ' ', map("-I$_", @INC);
#$perl = "perl $inc";
my $perl = "$Config{perlpath} $inc";
print "Using perl at `$perl'\n" if $trace>1;

### Pointer casting test for 64 bit architectures

print "Testing pointer to int casting...\n";
system "$perl ptrtstrun.pl";

&Net::SSLeay::load_error_strings();
&Net::SSLeay::SSLeay_add_ssl_algorithms();
print &test(2, &Net::SSLeay::hello == 1);

my $cert_pem = "examples/cert.pem";
my $key_pem =  "examples/key.pem";

unless (-r $cert_pem && -r $key_pem) {
    print "### Making self signed certificate just for these tests...\n"
	if $trace;
    
    open F, "openssl_path" or die "Can't read `./openssl_path': $!\n";
    $ssleay_path = <F>;
    close F;
    chomp $ssleay_path;

    system "$perl examples/makecert.pl examples $ssleay_path $silent";
    print "    certificate done.\n\n" if $trace;
}

unless ($pid = fork) {
    print "\tSpawning a test server on port 1212, pid=$$...\n" if $trace;
    $redir = $trace<3 ? '>>sslecho.log 2>&1' : '';
    exec("$perl examples/sslecho.pl 1212 $cert_pem $key_pem $redir");
}
sleep 1;  # if server is slow

$res = `$perl examples/sslcat.pl 127.0.0.1 1212 ssleay-test`;
print $res if $trace>1;
print &test(3, ($res =~ /SSLEAY-TEST/));

$res = `$perl examples/minicli.pl 127.0.0.1 1212 another`;
print $res if $trace>1;
print &test(4, ($res =~ /ANOTHER/));

$res = `$perl examples/callback.pl 127.0.0.1 1212 examples`;
print $res if $trace>1;
print &test(5, ($res =~ /OK\s*$/));

$bytes = $mb * 1024 * 1024;
print "\tSending $mb MB over localhost, may take a while (and some VM)...\n"
    if $trace;
$secs = time;
$res = `$perl examples/bulk.pl 127.0.0.1 1212 $bytes`;
print $res if $trace>1;
$secs = (time - $secs) || 1;
print "\t\t...took $secs secs (" . int($mb*1024/$secs). " KB/s)\n" if $trace;
print &test(6, ($res =~ /OK\s*$/));

kill $pid;  # We don't need that server any more

$res = `$perl examples/cli-cert.pl $cert_pem $key_pem examples`;
print $res if $trace>1;
print &test(7, ($res =~ /client cert: Subject Name: \/C=XX/));

print "\tSending $mb MB over pipes, may take a while (and some VM)...\n"
    if $trace;
$secs = time;
$res = `$perl examples/stdio_bulk.pl $cert_pem $key_pem $bytes`;
print $res if $trace>1;
$secs = (time - $secs) || 1;
print "\t\t...took $secs secs (" . int($mb*1024/$secs). " KB/s)\n" if $trace;
print &test(8, ($res =~ /OK\s*$/));

#app.iplanet.com
my @sites = qw(
www.openssl.org
www.cdw.com
banking.wellsfargo.com
secure.worldgaming.net
www.engelschall.com
www.ubs.com
	    );
if ($trace) {
print "    Now about to contact external sites...\n\twww.bacus.pt\n";
print map "\t$_\n", @sites;
print "    You have 5 seconds of time to hit Ctrl-C if you do not like this.\n";
print "    So far there were no errors in tests.\n" unless $errors;
print "*** $errors tests failed already.\n" if $errors;
print "    Following tests _will_ fail if you do not have network\n"
    . "    connectivity (or if the servers are down or have changed).\n";
sleep 5;
}

print &test('9 www.bacus.pt', &Net::SSLeay::sslcat("www.bacus.pt", 443,
				 "get\n\r\n\r") =~ /<TITLE>/);

sub test_site ($$) {
    my ($test_nro, $site) = @_;
    my ($p, $r) = ('','');
    my %h;
    warn "Trying $site...\n";
    $Net::SSLeay::trace=0;
    $Net::SSLeay::version=0;
    
    ($p, $r, %h) = Net::SSLeay::get_https($site, 443, '/');
    if (!defined($h{SERVER})) {
	print &test("$test_nro $site ($r)", scalar($r =~ /^HTTP\/1/s));
	print "\t$site, initial attempt with auto negotiate failed\n";

	$Net::SSLeay::trace=3;
	$Net::SSLeay::version=2;
	print "\tset version to 2\n";
	($p, $r, %h) = Net::SSLeay::get_https($site, 443, '/');
	
	$Net::SSLeay::version=3;
	print "\tset version to 3\n";
	($p, $r, %h) = Net::SSLeay::get_https($site, 443, '/');
	$Net::SSLeay::trace=0;
    }
    
    print join '', map("\t$_=>$h{$_}\n", sort keys %h) if $trace>1;

    if (defined($h{SERVER})) {
	print &test("$test_nro $site ($h{SERVER})", scalar($r =~ /^HTTP\/1/s));
    } else {
	print &test("$test_nro $site ($r)", scalar($r =~ /^HTTP\/1/s));
    }
}

my $i = 10;
my $s;
for $s (@sites) {
    &test_site($i++, $s );
}

die "*** WARNING: There were $errors errors in the tests.\n" if $errors;
print "All tests completed OK.\n" if $trace;
__END__
