#!/usr/bin/perl
# 23.6.1998, Sampo Kellomaki <sampo@iki.fi>
# 30.7.1999, upgraded for OpenSSL-0.9.3a --Sampo
# 7.4.2001,  upgraded to OpenSSL-0.9.6a --Sampo
# 15.4.2001, fixed little bug in ssl directory detection --Sampo
# 18.7.2001, fixed numerous issues reported by Eric A Selber
#	     <eselber@briefcase.com> that made Windows builds painful --Sampo
# 20.8.2001, tweaked path editing, thanks Gordon Lack <gml4410@ggr.co.uk> --Sampo
#
# Configuration script for Net::SSLeay.pm

$usage = <<USAGE
Usage: ./Makefile.PL [-windows] [-rsaref] [-m|-t] [OpenSSL installation path]
           -m and -t  will automatically build and test, respectively
           -d         builds and tests verbosely
           -rsaref    provides support for linking against rsaref
           -windows   sets library paths for windows build
E.g:   ./Makefile.PL -d

Note: For Windows builds openssl installation path must always be given.
USAGE
    ;
die $usage if grep /^--?[hv?]/i, @ARGV;

$windows = shift if $ARGV[0] eq '-windows';
$rsaref  = shift if $ARGV[0] eq '-rsaref';
$make_it = shift if $ARGV[0] eq '-m';
$test_it = shift if $ARGV[0] eq '-t';
$debug = $test_it = shift if $ARGV[0] eq '-d';
if (@ARGV) {
    $openssl_path = shift;
} else {
    # It seems at least Redhat installs OpenSSL in /usr ...
    $openssl_path = '/usr' if -x '/usr/bin/openssl' || -x '/usr/sbin/openssl';
    $openssl_path = '/opt/ssl' if -x '/opt/ssl/bin/openssl'
	|| -x '/opt/ssl/sbin/openssl';
    $openssl_path = '/usr/local/ssl' if -x '/usr/local/ssl/bin/openssl';
}

$openssl_vers = '0.9.6b';

print "Checking for OpenSSL-$openssl_vers or newer...\n";

while (1) {
    $exe_path = "$openssl_path/bin/openssl";
    last if -x $exe_path;
    $exe_path = "$openssl_path/bin/openssl.exe";
    last if -x $exe_path;
    $exe_path = "$openssl_path/sbin/openssl";
    last if -x $exe_path;

    print "I could not find your OpenSSL in `$openssl_path'\n";
    print "Please provide OpenSSL-$openssl_vers installation directory (get from\n"
	." http://www.openssl.org/ if you don't have it; please note that\n"
	    ." SSLeay is no longer supported, see README) (C-c to abort):\n";
    $openssl_path = <STDIN>;
    chomp $openssl_path;
}

($openssl_bin_path = $exe_path) =~ s%/openssl(\.exe)?$%%;

$vers = `$exe_path version`
    or die "Couldn't run `$exe_path' ($?)\n";

unless (($lib_name, $maj, $min, $letter) = $vers =~
	/^(OpenSSL)\s+(\d+\.\d+)\.(\d+)([a-z]*)/) {
    die "Openssl version test failed (`$vers' was returned, but\n"
    . "couldn't be parsed). Either you have bogus OpenSSL or a new version\n"
    . "has changed the version number format.\n";
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

warn "openssl-0.9.6a and some earlier versions have weaknesses (read CHANGES file in the openssl-0.9.6b distribution, www.openssl.org), upgrading to openssl-0.9.6b is recommended.\n"
    if $maj eq '0.9' && $min == 6 && $letter lt 'b';

open F, ">openssl_path" or die "Can't write ./openssl_path: $!";
print F $openssl_bin_path;  # used by test.pl and examples/makecert.pl
close F;

### The windows option tweaking details supplied by
### Eric A Selber <eselber@briefcase.com>. This is
### still experimental until I get success reports.

if ($windows) {
    warn "RSAREF build on Windows not supported out of box" if $rsaref;
    $libs = "-llibeay32 -lssleay32";
} else {
    ### There is some confusio over the correct ordering
    ### of these libraries. Tarang Kumar Patel <mombasa@ptolemy.arc.nasa.gov>
    ### reports this order to work on Solaris 7 and openssl-0.9.6b
    $libs = $rsaref ? "-lssl -lcrypto -lRSAglue -lrsaref" : "-lssl -lcrypto";
    
    ### old order which might work on some platforms
    #$libs = $rsaref ? "-lssl -lRSAglue -lcrypto -lrsaref" : "-lssl -lcrypto";
}

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME	=> 'Net::SSLeay',
    VERSION_FROM => 'SSLeay.pm', # finds $VERSION
    DIR         => 'Net-SSLeay-Handle-0.50',
    DEFINE	=> '',     # e.g., '-DHAVE_SOMETHING' 
    DISTNAME    => 'Net_SSLeay.pm',
    dist        => { COMPRESS => 'gzip', SUFFIX => 'gz', },
    LIBS	=> ["-L$openssl_path -L$openssl_path/lib $libs"],
    INC 	=> "-I$openssl_path/include",
# Uncomment (and edit) following for debugging with gdb
#    LIBS	=> ['-L/usr/src/openssl-0.9.3a -lssl -lcrypto'],
#    INC	=> '-I/usr/src/openssl-0.9.3a/include',
#    OPTIMIZE   => '-g',
);

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
#WriteMakefile(
#    'NAME'	   => 'Net::SSLeay::Handle',
#    'VERSION_FROM' => 'Handle.pm', # finds $VERSION
#);

$ENV{TEST_TRACE} = 2 if $debug;
exec "make" if $make_it;
exec "make test" if $test_it;

__END__
