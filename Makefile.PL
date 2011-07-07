use strict;
use warnings;
use ExtUtils::MakeMaker;

my %attr = (
    NAME                => 'IPTables::SubnetSkeleton',
    AUTHOR              => q{Jesper Dangaard Brouer <hawk@comx.dk>},
    VERSION_FROM        => 'lib/IPTables/SubnetSkeleton.pm',
    ABSTRACT_FROM       => 'lib/IPTables/SubnetSkeleton.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'IPTables-SubnetSkeleton-*' },
);

(my $mmv = ExtUtils::MakeMaker->VERSION) =~ s/_//g;
$mmv >= 6.31 and $attr{LICENSE} = 'GPL';

WriteMakefile (%attr);
