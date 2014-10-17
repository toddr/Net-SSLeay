use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::SSLeay',
    'VERSION_FROM' => 'SSLeay.pm', # finds $VERSION
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'LIBS'	=> ['-L/usr/local/ssl/lib -lssl -lcrypto'],   # e.g., '-lm' 
    'INC'	=> '-I/usr/local/ssl/include',  # e.g., '-I/usr/include/other' 
# Uncomment (and edit) following for debugging with gdb
#    'LIBS'	=> ['-L/usr/src/SSLeay-0.9.0 -lssl -lcrypto'],
#    'INC'	=> '-I/usr/src/SSLeay-0.9.0/include',
#    'OPTIMIZE'  => '-g',
);
