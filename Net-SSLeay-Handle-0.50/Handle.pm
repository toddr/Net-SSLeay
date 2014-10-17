# $Id: Handle.pm,v 1.7 2002/06/05 18:25:46 sampo Exp $

package Net::SSLeay::Handle;

require 5.005_03;
use strict;

use Socket;
use Net::SSLeay;

require Exporter;

use vars qw(@ISA @EXPORT_OK $VERSION);
@ISA = qw(Exporter);
@EXPORT_OK = qw(shutdown);
$VERSION = '0.52';

#=== Class Variables ==========================================================
#
# %Filenum_Object holds the attributes (see bottom of TIEHANDLE) of tied
# handles keyed by fileno.  This was the only way I could figure out how
# to "attach" attributes to a returned glob reference.
#
#==============================================================================

my $Initialized;       #-- only _initialize() once
my %Filenum_Object;    #-- hash of hashes, keyed by fileno()                       
my $Debug = 0;         #-- pretty hokey

#== Tie Handle Methods ========================================================
#
# see perldoc perltie for details.
#
#==============================================================================

sub TIEHANDLE {
    my ($class, $socket, $port) = @_;
    $Debug > 10 and print "TIEHANDLE(@{[join ', ', @_]})\n";

  UNIVERSAL::isa($socket, 'GLOB')
      or $socket = $class->make_socket($socket, $port);
    #ref $socket eq "GLOB" or $socket = $class->make_socket($socket, $port);

    $class->_initialize();

    my $ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
    my $ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");

    my $fileno = fileno($socket);

  Net::SSLeay::set_fd($ssl, $fileno);   # Must use fileno

    my $resp = Net::SSLeay::connect($ssl);

    $Debug and print "Cipher '" . Net::SSLeay::get_cipher($ssl) . "'\n";

    $Filenum_Object{$fileno} = {
        ssl    => $ssl, 
        ctx    => $ctx,
        socket => $socket,
        fileno => $fileno,
    };

    return bless $socket, $class;
}

sub PRINT {
    my $socket = shift;

    my $ssl  = _get_ssl($socket);
    my $resp = 0;
    for my $msg (@_) {
        defined $msg or last;
        $resp = Net::SSLeay::write($ssl, $msg) or last;
    }
    return $resp;
}

sub READLINE {
    my $socket = shift;
    my $ssl  = _get_ssl($socket);
    my $line = Net::SSLeay::ssl_read_until($ssl); 
    return $line ? $line : undef;
}

sub CLOSE {
    my $socket = shift;
    my $fileno = fileno($socket);
    $Debug > 10 and print "close($fileno)\n";
    my $self = $socket->_get_self();
    delete $Filenum_Object{$fileno};
  Net::SSLeay::free ($self->{ssl});
  Net::SSLeay::CTX_free ($self->{ctx});
    close $socket;
}

sub FILENO  { fileno($_[0]) }


#== Exportable Functions  ======================================================

#--- shutdown(\*SOCKET, $mode) ------------------------------------------------
# Calls to the main shutdown() don't work with tied sockets created with this
# module.  This shutdown should be able to distinquish between tied and untied
# sockets and do the right thing.
#------------------------------------------------------------------------------

sub shutdown {
    my ($socket, @params) = @_;

    my $obj = _get_self($socket);
    $obj and $socket = $obj->{socket};
    return shutdown($socket, @params);
}

#==============================================================================

sub debug {
    my ($class, $debug) = @_;
    my $old_debug = $Debug;
    @_ >1 and $Debug = $debug || 0;
    return $old_debug;
}

#=== Internal Methods =========================================================

sub make_socket {
    my ($class, $host, $port) = @_;
    $Debug > 10 and print "_make_socket(@{[join ', ', @_]})\n";
    $host ||= "localhost";
    $port ||= 443;

    if ($Net::SSLeay::proxyhost) {

#    $port = getservbyname($port, 'tcp') unless $port =~ /^\d+$/;
	my $dest_ip = gethostbyname($Net::SSLeay::proxyhost);
	my $host_params = sockaddr_in($Net::SSLeay::proxyport, $dest_ip);
	my $socket = \*S;
	socket($socket, &PF_INET(), &SOCK_STREAM(), 0)    or die "socket: $!";
	connect($socket, $host_params)              or die "connect: $!";
	my $old_select = select($socket); $| = 1; select($old_select);
	
	print $socket "CONNECT $host:$port HTTP/1.0$Net::SSLeay::proxyauth$Net::SSLeay::CRLF$Net::SSLeay::CRLF";
	my $line = <$socket>;
	return $socket;

    } else {

#    $port = getservbyname($port, 'tcp') unless $port =~ /^\d+$/;
	my $dest_ip = gethostbyname($host);
	my $host_params = sockaddr_in($port, $dest_ip);
	my $socket = \*S;
	socket($socket, &PF_INET(), &SOCK_STREAM(), 0)    or die "socket: $!";
	connect($socket, $host_params)              or die "connect: $!";
	my $old_select = select($socket); $| = 1; select($old_select);
	return $socket;
    }
}

sub _initialize {
    $Initialized++ and return;
  Net::SSLeay::load_error_strings();
  Net::SSLeay::SSLeay_add_ssl_algorithms();
  Net::SSLeay::randomize();
}

#--- _get_self($socket) -------------------------------------------------------
# Returns a hash containing attributes for $socket (= \*SOMETHING) based
# on fileno($socket).  Will return undef if $socket was not created here.
#------------------------------------------------------------------------------

sub _get_self {
    return $Filenum_Object{fileno(shift)};
}

#--- _get_ssl($socket) --------------------------------------------------------
# Returns a the "ssl" attribute for $socket (= \*SOMETHING) based
# on fileno($socket).  Will cause a warning and return undef if $socket was not
# created here.
#------------------------------------------------------------------------------

sub _get_ssl {
    my $socket = shift;
    return $Filenum_Object{fileno($socket)}->{ssl};
}

1;
__END__

=head1 NAME

Net::SSLeay::Handle - Perl module that lets SSL (HTTPS) sockets be
handled as standard file handles.

=head1 SYNOPSIS

  use Net::SSLeay::Handle qw/shutdown/;
  my ($host, $port) = ("localhost", 443);

  tie(*SSL, "Net::SSLeay::Handle", $host, $port);

  print SSL "GET / HTTP/1.0\r\n";
  shutdown(\*SSL, 1);
  print while (<SSL>);
  close SSL;                                                       
  

=head1 DESCRIPTION

Net::SSLeay::Handle allows you to request and receive HTTPS web pages
using "old-fashion" file handles as in:

    print <SSL> "GET / HTTP/1.0\r\n";

and

    print while (<SSL>);

If you export the shutdown routine, then the only extra code that
you need to add to your program is the tie function as in:

    my $socket;
    if ($scheme eq "https") {
        tie(*S2, "Net::SSLeay::Handle", host, $port);
        $socket = \*S2;
    else {
        $socket = Net::SSLeay::Handle->make_socket(host, $port);
    }
    print $socket $request_headers;
    ... 

=head2 USING EXISTING SOCKETS

One of the motivations for writing this module was to avoid
duplicating socket creation code (which is mostly error handling).
The calls to tie() above where it is passed a $host and $port is
provided for convenience testing.  If you already have a socket
connected to the right host and port, S1, then you can do something
like:

    my $socket \*S1;
    if ($scheme eq "https") {
        tie(*S2, "Net::SSLeay::Handle", $socket);
        $socket = \*S2;
    }
    my $last_sel = select($socket); $| = 1; select($last_sel);
    print $socket $request_headers;
    ... 

Note: As far as I know you must be careful with the globs in the tie()
function.  The first parameter must be a glob (*SOMETHING) and the
last parameter must be a reference to a glob (\*SOMETHING_ELSE) or a
scaler that was assigned to a reference to a glob (as in the example
above)

Also, the two globs must be different.  When I tried to use the same
glob, I got a core dump.

=head2 EXPORT

None by default.

You can export the shutdown() function.

It is suggested that you do export shutdown() or use the fully
qualified Net::SSLeay::Handle::shutdown() function to shutdown SSL
sockets.  It should be smart enough to distinguish between SSL and
non-SSL sockets and do the right thing.

=head1 EXAMPLES

  use Net::SSLeay::Handle qw/shutdown/;
  my ($host, $port) = ("localhost", 443);

  tie(*SSL, "Net::SSLeay::Handle", $host, $port);

  print SSL "GET / HTTP/1.0\r\n";
  shutdown(\*SSL, 1);
  print while (<SSL>);
  close SSL; 

=head1 TODO

Better error handling.  Callback routine?

=head1 CAVEATS

Tying to a file handle is a little tricky (for me at least).

The first parameter to tie() must be a glob (*SOMETHING) and the last
parameter must be a reference to a glob (\*SOMETHING_ELSE) or a scaler
that was assigned to a reference to a glob ($s = \*SOMETHING_ELSE).
Also, the two globs must be different.  When I tried to use the same
glob, I got a core dump.

I was able to associate attributes to globs created by this module
(like *SSL above) by making a hash of hashes keyed by the file head1.

Support for old perls may not be 100%. If in trouble try 5.6.0 or
newer.

=head1 AUTHOR

Jim Bowlin jbowlin@linklint.org

=head1 SEE ALSO

Net::SSLeay

=cut

