use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Net::SSLeay::Handle',
    'VERSION_FROM'	=> 'Handle.pm', # finds $VERSION
    'PREREQ_PM'		=> {}, # e.g., Net::SSLeay => 1.07
);
