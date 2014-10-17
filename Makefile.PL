#!/usr/bin/perl
# 23.6.1998, Sampo Kellomaki <sampo@iki.fi>
#
# Configuration script for Net::SSLeay.pm
#
# Usage: ./Makefile.PL [-m|-t] [SSLeay installation path]
#              -m and -t will automatically build and test, respectively

$make_it = shift if $ARGV[0] eq '-m';
$test_it = shift if $ARGV[0] eq '-t';
$ssleay_path = shift || '/usr/local/ssl';

print "Checking for SSLeay-0.9.0...\n";

until (-x "$ssleay_path/bin/ssleay") {
    print "I could not find your SSLeay in `$ssleay_path'\n";
    print "Please provide SSLeay-0.9.0 installation directory (C-c to abort):\n";
    $ssleay_path = <STDIN>;
    chomp $ssleay_path;
}

$vers = `$ssleay_path/bin/ssleay version`
    or die "Couldn't run `$ssleay_path/bin/ssleay' ($?)($!)\n";

($maj, $min) = $vers =~ /^SSLeay\s+(\d+\.\d+)\.(\d+)/ or
    die "SSLeay version test failed (`$vers' was returned, but\n"
    . "couldn't be parsed). Either you have bogus SSLeay or Eric\n"
    . "has changed version number format.\n";

print "You have SSLeay-$maj.$min installed in $ssleay_path\n";

die "That's too old. Please upgrade to SSLeay-0.9.0\n"
    . "before trying to install this module. If you can't upgrade,\n"
    . "Net_SSLeay.pm-0.04 still works for you.\n"
    if $maj eq '0.6' && $min >=1;

die "That's too old. Please upgrade to SSLeay-0.9.0\n"
    . "before trying to install this module.\n"
    if $maj < 0.9;

warn "That's is newer than what this module was tested with. You should\n"
    . "consider checking if there is a newer release of this module\n"
    . "available. Everything will probably work OK, though.\n"
    if $maj > 0.9 || $min > 0;

open F, ">ssleay_path" or die "Can't write ssleay_path: $!\n";
print F $ssleay_path;
close F;

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	   => 'Net::SSLeay',
    'VERSION_FROM' => 'SSLeay.pm', # finds $VERSION
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'DISTNAME'  => 'Net_SSLeay.pm',
    'dist'      => { COMPRESS => 'gzip', SUFFIX => 'gz', },
    'LIBS'	=> ["-L$ssleay_path -L$ssleay_path/lib -lssl -lcrypto"],
    'INC'	=> "-I$ssleay_path/include",
# Uncomment (and edit) following for debugging with gdb
#    'LIBS'	=> ['-L/usr/src/SSLeay-0.9.0 -lssl -lcrypto'],
#    'INC'	=> '-I/usr/src/SSLeay-0.9.0/include',
#    'OPTIMIZE'  => '-g',
);

exec "make test" if $test_it;
exec "make" if $make_it;

__END__
