use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'IPTables::SubnetSkeleton',
    AUTHOR              => q{Jesper Dangaard Brouer <hawk@comx.dk>},
    VERSION_FROM        => 'lib/IPTables/SubnetSkeleton.pm',
    ABSTRACT_FROM       => 'lib/IPTables/SubnetSkeleton.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'GPL')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'IPTables-SubnetSkeleton-*' },
);
