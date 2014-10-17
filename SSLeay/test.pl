# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN {print "1..5\n";}
END {print "not ok 1\n" unless $loaded;}
use Net::SSLeay;
$loaded = 1;
print "ok 1\n";
print &Net::SSLeay::hello == 1 ? "ok 2\n" : "not ok 2\n";
print Net::SSLeay::cat("brutus.neuronio.pt", 443, "get\n\r\n\r") =~ /<TITLE>/ ? "ok 3\n" : "not ok 3\n";

######################### End of black magic.

chdir('examples');
system('./sslecho.pl 1212&');
sleep 5;
print "Server started, you have to kill it by hand...\n";

$host = `hostname`;
chop $host;
print "Hostname '$host'\n";

$res = `./sslcat.pl $host 1212 ssleay-test`;
print STDOUT "Result '$res': \n"
    . (($res =~ /SSLEAY-TEST/) ? "ok 4\n" : "not ok 4\n");

$res = `./minicli.pl $host 1212 another`;
print STDOUT "Result '$res': \n"
    . (($res =~ /ANOTHER/) ? "ok 5\n" : "not ok 5\n");
