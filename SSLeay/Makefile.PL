use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::SSLeay',
    'VERSION_FROM' => 'SSLeay.pm', # finds $VERSION
    'LIBS'	=> ['-L/usr/local/ssl/lib -lssl -lcrypto'],   # e.g., '-lm' 
    'DEFINE'	=> '',     # e.g., '-DHAVE_SOMETHING' 
    'INC'	=> '-I/usr/local/ssl/include',  # e.g., '-I/usr/include/other' 
);
