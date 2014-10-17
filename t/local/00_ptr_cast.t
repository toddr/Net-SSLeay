#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;
use Test::More tests => 5;
use Symbol qw(gensym);
use IPC::Open3;
use Config;

my $input  = File::Spec->catfile(qw( t local ptr_cast_test.c ));
my $output = File::Spec->catfile(qw( t local ptr_cast_test   ));

unlink $output;

my $out = gensym();
my $err = gensym();

my @extraargs;
my $cmd;
if($^O eq 'MSWin32' && $Config{cc} eq 'cl') {
  push(@extraargs, '/nologo ' . $Config{libs});
  $cmd = "$Config{cc} /Fe$output $input " . join(' ', @extraargs);
}
else {
    push(@extraargs, '-Zexe') if $^O eq 'os2';
    $cmd = "$Config{cc} $Config{ccflags} -o $output $input " . join(' ', @extraargs)
}
diag( "compiling test program with: $cmd" );
my $pid = open3(undef, $out, $err, $cmd);
waitpid $pid, 0;

is( $?, 0, 'compiling ptr_cast_test.c' );

is( do { local $/ = undef; <$err>}, '', 'STDERR empty after compiling' );

$pid = open3(undef, $out, $err, "./$output");
waitpid $pid, 0;

is( $?, 0, './ptr_cast_test exited with 0' );

like( do { local $/ = undef; <$out> }, qr/ptr_cast_test:\s+ok\s+/, 'casting pointer integer and back worked' );
ok( !do { local $/ = undef; <$err> }, 'STDERR empty after running' );
