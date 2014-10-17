#!/usr/bin/perl
# 24.6.1998, Sampo Kellomaki <sampo@iki.fi>
#
# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..11\n";}
END {print "not ok 1\n" unless $loaded;}
use Net::SSLeay qw(die_now die_if_ssl_error);
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

$trace = 1;  # 0=silent, 1=verbose, 2=debugging
$mb = 5;     # size of the bulk tests
$errors = 0;
$silent = $trace>1 ? '' : '>/dev/null 2>/dev/null';

sub test {
    my ($num, $test) = @_;
    $errors++ unless $test;
    return $test ? "ok $num\n" : "*** not ok $num\n\n"
}

&Net::SSLeay::load_error_strings();
&Net::SSLeay::SSLeay_add_ssl_algorithms();
print &test(2, &Net::SSLeay::hello == 1);

$cert_pem = "examples/cert.pem";
$key_pem =  "examples/key.pem";

unless (-r $cert_pem && -r $key_pem) {
    print "### Making self signed certificate just for these tests...\n"
	if $trace;
    
    open F, "ssleay_path" or die "Can't read `ssleay_path': $!\n";
    $ssleay_path = <F>;
    close F;
    chomp $ssleay_path;

    system "examples/makecert.pl examples $ssleay_path $silent";
    print "    certificate done.\n\n" if $trace;
}

$inc = join ' ', map("-I$_", @INC);
$perl = "perl $inc";

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

print "\tSending $mb MB over pipes, may take a while (and some VM)...\n"
    if $trace;
$secs = time;
$res = `$perl examples/stdio_bulk.pl $cert_pem $key_pem $bytes`;
print $res if $trace>1;
$secs = (time - $secs) || 1;
print "\t\t...took $secs secs (" . int($mb*1024/$secs). " KB/s)\n" if $trace;
print &test(7, ($res =~ /OK\s*$/));

if ($trace) {
print "### Now about to contact external sites...\n";
print "### You have 5 seconds of time to hit Ctrl-C "
    . "if you do not like this.\n";
print "    So far there were no errors in tests.\n" unless $errors;
print "*** $errors tests failed already.\n" if $errors;
print "    Following tests _will_ fail if you do not have network\n"
    . "    connectivity (or if the servers are down or have changed).\n";
sleep 5;
}

print &test('8 neuronio', &Net::SSLeay::sslcat("brutus.neuronio.pt", 443,
				 "get\n\r\n\r") =~ /<TITLE>/);

sub test_site {
    my ($test_nro, $site) = @_;
    my ($p, $r) = Net::SSLeay::get_https($site, 443, '/');
    print &test("$test_nro $site", scalar($r =~ /^HTTP\/1/s));
}

&test_site(9,  "www.cryptsoft.com");
&test_site(10, "www.cdw.com");
&test_site(11, "transact.netscape.com");

die "*** WARNING: There were $errors errors in the tests.\n" if $errors;
print "All tests completed OK.\n" if $trace;
__END__
