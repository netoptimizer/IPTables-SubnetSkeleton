use strict;
use warnings;
use ExtUtils::MakeMaker;

my %attr = (
    NAME                => 'IPTables::SubnetSkeleton',
    AUTHOR              => q{Jesper Dangaard Brouer <hawk@comx.dk>},
    VERSION_FROM        => 'lib/IPTables/SubnetSkeleton.pm',
    ABSTRACT            => 'SubnetSkeleton - Scalable iptables subnet based search tree',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More'         => 0,
	'Net::IPAddress'     => 0,
	'Log::Log4perl'      => 0,
	'IPTables::libiptc'  => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'IPTables-SubnetSkeleton-*' },
);

(my $mmv = ExtUtils::MakeMaker->VERSION) =~ s/_//g;
$mmv >= 6.31 and $attr{LICENSE} = 'GPL';

WriteMakefile (%attr);
