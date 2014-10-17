#!/usr/bin/perl
# 23.6.1998, Sampo Kellomaki <sampo@iki.fi>
# 30.7.1999, upgraded for OpenSSL-0.9.3a --Sampo
# 7.4.2001,  upgraded to OpenSSL-0.9.6a --Sampo
#
# Configuration script for Net::SSLeay.pm

$usage = <<USAGE
Usage: ./Makefile.PL [-rsaref] [-m|-t] [OpenSSL installation path]
           -m and -t  will automatically build and test, respectively
           -d         builds and tests verbosely
           -rsaref    provides support for linking against rsaref
E.g:   ./Makefile.PL -d
USAGE
    ;
die $usage if grep /^--?[hv?]/i, @ARGV;

$rsaref  = shift if $ARGV[0] eq '-rsaref';
$make_it = shift if $ARGV[0] eq '-m';
$test_it = shift if $ARGV[0] eq '-t';
$debug = $test_it = shift if $ARGV[0] eq '-d';
if (@ARGV) {
    $openssl_path = shift;
} else {
    # It seems at least Redhat installs OpenSSL in /usr ...
    $openssl_path = '/usr' if -x '/usr/bin/openssl' | '/usr/sbin/openssl';
    $openssl_path = '/opt/ssl' if -x '/opt/ssl/bin/openssl'
	| '/opt/ssl/sbin/openssl';
    $openssl_path = '/usr/local/ssl' if -x '/usr/local/ssl/bin/openssl';
}

$openssl_vers = '0.9.6a';

print "Checking for OpenSSL-$openssl_vers or newer...\n";

until (-x "$openssl_path/bin/openssl" | -x "$openssl_path/sbin/openssl") {
    print "I could not find your OpenSSL in `$openssl_path'\n";
    print "Please provide OpenSSL-$openssl_vers installation directory (get from\n"
	. " http://www.openssl.org/ if you don't have it; please note that\n"
	    ." SSLeay is no longer supported, see README) (C-c to abort):\n";
    $openssl_path = <STDIN>;
    chomp $openssl_path;
}

$openssl_bin_path = -x "$openssl_path/bin/openssl" ?
    "$openssl_path/bin" : "$openssl_path/sbin";

$vers = `$openssl_bin_path/openssl version`
    or die "Couldn't run `$openssl_bin_path/bin/openssl' ($?)\n";

unless (($lib_name, $maj, $min, $letter) = $vers =~
	/^(OpenSSL)\s+(\d+\.\d+)\.(\d+)([a-z]*)/) {
    die "Openssl version test failed (`$vers' was returned, but\n"
    . "couldn't be parsed). Either you have bogus OpenSSL or a new version\n"
    . "has changed version number format.\n";
}

print "You have $lib_name-$maj.$min$letter installed in $openssl_path\n";

die "That's too old. Please upgrade to OpenSSL-$openssl_vers\n"
    . "before trying to install this module. If you can't upgrade,\n"
    . "see README for other options.\n"
    if $maj eq '0.9' && $min < 3;

warn "That's is newer than what this module was tested with ($openssl_vers). You should\n"
    . "consider checking if there is a newer release of this module\n"
    . "available. Everything will probably work OK, though.\n"
    if $maj > 0.9 || $min > 6;

open F, ">openssl_path" or die "Can't write ./openssl_path: $!";
print F $openssl_bin_path;  # used by test.pl and examples/makecert.pl
close F;

$libs = $rsaref ? "-lssl -lRSAglue -lcrypto -lrsaref" : "-lssl -lcrypto";

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	   => 'Net::SSLeay',
    'VERSION_FROM' => 'SSLeay.pm', # finds $VERSION
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'DISTNAME'  => 'Net_SSLeay.pm',
    'dist'      => { COMPRESS => 'gzip', SUFFIX => 'gz', },
    'LIBS'	=> ["-L$openssl_path -L$openssl_path/lib $libs"],

### Win32 build: uncommend LIBS above and edit LIBS below according to your
### 
#    'LIBS'	=> ["'-L/Program Files/DevStudio/VC/lib' -L$openssl_path -L$openssl_path/lib $libs"],
    'INC'	=> "-I$openssl_path/include",
# Uncomment (and edit) following for debugging with gdb
#    'LIBS'	=> ['-L/usr/src/openssl-0.9.3a -lssl -lcrypto'],
#    'INC'	=> '-I/usr/src/openssl-0.9.3a/include',
#    'OPTIMIZE'  => '-g',
);

$ENV{TEST_TRACE} = 2 if $debug;
exec "make" if $make_it;
exec "make test" if $test_it;

__END__
