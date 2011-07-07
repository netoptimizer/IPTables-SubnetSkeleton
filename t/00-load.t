#!perl -T

use Test::More tests => 2;

BEGIN {
    use_ok( 'IPTables::SubnetSkeleton' ) || print "Bail out!
";
    use_ok( 'IPTables::Interface' ) || print "Bail out!
";
}

diag( "Testing IPTables::SubnetSkeleton $IPTables::SubnetSkeleton::VERSION, Perl $], $^X" );
