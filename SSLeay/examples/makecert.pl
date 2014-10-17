#!/usr/bin/perl
# 19.6.1998, Sampo Kellomaki <sampo@iki.fi>
# Make a self signed cert

$ssleay_path = "/usr/local/ssl/bin";
$dir = shift;

open (REQ, "|$ssleay_path/req -config $dir/req.conf "
      . "-x509 -days 36500 -new -keyout $dir/key.pem >$dir/cert.pem")
    or die "cant open req. check your path ($!)";
print REQ <<DISTINGUISHED_NAME;
XX
Net::SSLeay test land
Test City
Net::SSLeay Organization
Test Unit
127.0.0.1
sampo\@iki.fi
DISTINGUISHED_NAME
    ;
close REQ;
system "$ssleay_path/verify $dir/cert.pem";  # Just to check

### Prepare examples directory as certificate directory

$hash = `$ssleay_path/x509 -inform pem -hash -noout <$dir/cert.pem`;
chomp $hash;
unlink "$dir/$hash.0";
symlink $cert_pem, "$dir/$hash.0" or die "Can't symlink $dir/$hash.0 ($!)";

__END__
