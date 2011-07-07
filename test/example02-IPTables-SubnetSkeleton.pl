#!/usr/bin/perl -w

# Trick to alter @INC runtime
use File::Basename;
BEGIN {our $dir = dirname($0);}
use lib "$dir/../blib/lib";
use lib "$dir/../blib/arch";

use Data::Dumper;

use Log::Log4perl qw(:easy); Log::Log4perl->easy_init($ERROR);

use IPTables::SubnetSkeleton;

# Define the subnet CIDR splitting points
my @netmasks = (8, 18, 20, 22, 24, 26, 28);

# Create two subnet object, IP source vs. destination matching
$subnet_src =
   IPTables::SubnetSkeleton::new("shortname", "src", "filter", @netmasks);
$subnet_dst =
   IPTables::SubnetSkeleton::new("shortname", "dst", "filter", @netmasks);

# Connect subnet skeleton to build-in chain "FORWARD".
$subnet_src->connect_to("FORWARD");
$subnet_dst->connect_to("FORWARD");

# Create a chain for a customer/user
my $userchain = "user42";
if ( ! $subnet_src->iptables_chain_exist("$userchain") ) {
    $subnet_src->iptables_chain_new($userchain);
}
$subnet_src->iptables_insert("user42", "", "ACCEPT"); #Accept all traffic

# SubnetSkeleton: Add a IP match that will jump to $userchain
my $IP = "10.0.0.42";
$subnet_src->insert_element("$IP", "$userchain");
$subnet_dst->insert_element("$IP", "$userchain");

# Add an IP and remove its again
my $IP2 = "10.0.1.43";
$subnet_dst->insert_element("$IP", "$userchain");
$subnet_dst->disconnect_element("$IP", "$userchain");

# Remember to commit iptables changes to kernel
$subnet_src->iptables_commit();
