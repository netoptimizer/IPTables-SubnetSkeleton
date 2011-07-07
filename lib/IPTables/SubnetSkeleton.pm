package IPTables::SubnetSkeleton;

use strict;
use warnings;
use Carp;

# Net::IPAddress is such a small module, that we have included it in
# this package.
use Net::IPAddress;

use IPTables::Interface;

# Local module vars (that perhaps should be moved somewhere else).
my $packageid=__PACKAGE__;

BEGIN {
     use Exporter ();
     our ($VERSION, @ISA, @EXPORT, @EXPORT_OK, %EXPORT_TAGS);

     # Package version
     $VERSION     = 0.3001;

     @ISA         = qw(Exporter);
     @EXPORT      = qw(&insert_element &print_cidr_breaks &connect_to
                       &worstcase_search);
}

# new($skeleton_name, $skeleton_type, @cidr_breaks)
#
# Create a new SubnetSkeleton Object.
sub new
{
    my ($skeleton_name, $skeleton_type, $table, @cidr_breaks) = @_;

    my $self = {};

    $self->{'skeleton_name'}   = $skeleton_name;
   #$self->{'skeleton_type'}   = $skeleton_type;
    $self->{'cidr_breaks'}     = \@cidr_breaks;

    # Netfilter table (possible: nat, mangle, filter, raw)
    if (defined $table && $table ne "") {
	$self->{'netfilter_table'} = $table;
    } else {
	# Defaults to table "filter"
	$self->{'netfilter_table'} = "filter";
    }

    # Create a IPTables object and store it in this object.
    my $ipt_obj = IPTables::Interface::new($self->{'netfilter_table'});
    $self->{'iptables_object'} = $ipt_obj;

    bless($self);
    $self->skeleton_type($skeleton_type);

    # TODO: Implement a module Error function
    if ( ! $self->validate_cidr_breaks() ) {
	die "[ERROR] Invalid CIDR breaks.";
    }

    # Create the base skeleton chain
    my $chain = $self->get_chainname_skeleton;
    if ( ! $self->iptables_chain_exist("$chain") ) {
	$self->iptables_chain_new("$chain");
    }

    return $self;
}

sub get_iptables_object()
{
    my $self = shift;
    my $ipt_obj =  $self->{'iptables_object'};
    return $ipt_obj;
}

# connect_to($chainname)
#
# The subnet skeleton is not by default connected to
# any build-in chain.  You need to explicitly connect
# it to the desired chain using this function.
sub connect_to($)
{
    my $self          = shift;
    my $connect_chain = shift;
    my $success;

    my $jump_chain = $self->get_chainname_skeleton();

    # Exist: $connect_chain
    if ( ! $self->iptables_chain_exist("$connect_chain") ) {
	carp "WARNING: Cannot connect_to(\"$connect_chain\") as it does not exist.\n";
    } else {
	# Exist: $jump_chain
	if ( ! $self->iptables_chain_exist("$jump_chain") ) {
	    # If our own base skeleton chain does not exist, it must be created!
	    $self->iptables_chain_new("$jump_chain");
	    #carp "WARNING: Cannot use jump_chain \"$jump_chain\" as it does not exist.\n";
	}
	$success = $self->iptables_append("$connect_chain", "", "$jump_chain");
    }
    return $success;
}

# validate_cidr_breaks()
#
# Validates the CIDR breaks to lie within the 1..31 range.
# returns 1 if this is the case and 0 otherwise.
#
sub validate_cidr_breaks
{
    my $self = shift;

    my $cidr;
    my $cidr_old = 0;

    foreach $cidr (@{$self->{'cidr_breaks'}}) {
	#
	# Verify between 1 and 31
	if ($cidr < 1 || $cidr > 31) {
	    return 0;
	}
	#
	# Verify CIDR breaks is in increasing order.
	if ($cidr < $cidr_old) {
	    return 0;
	}
	$cidr_old = $cidr;
    }

    return 1;
}

# print_cidr_breaks
#
# Prints current CIDR breaks
sub print_cidr_breaks
{
    my $self = shift;

    my $i;

    my $cidr_ref = $self->{'cidr_breaks'};
    my $num_elem = $#{$cidr_ref};

    print("CIDR breaks:$num_elem\n");
    foreach $i (@{$cidr_ref}) {
	printf("%s\n", $i);
    }
}

# skeleton_type($skeleton_type)
#
# Sets the skeleton type to either 'src' or 'dst' depending
# on whether you want to match on Source or Destination IP addresses.
sub skeleton_type($)
{
    my $self = shift;
    my $type = shift;

    if ($type eq 'src') {
	$self->{'skeleton_type'} = 'src';
    } elsif ($type eq 'dst') {
	$self->{'skeleton_type'} = 'dst';
    } else {
	die("${packageid}::skeleton_type not 'src' or 'dst'");
    }
}

# Future idea function
sub find_longest_search_path()
{
}

# Future idea function
sub show_tree()
{

}

# What is the worst case search lenght
sub worstcase_search()
{
    my $self = shift;

    my $cidr;
    my $max_search;
    my @cidr_list = @{$self->{'cidr_breaks'}};

    my $jumps = @cidr_list + 1; #the lenght + the initial chain
    my $leaf_network_elements = (1 << (32 - $cidr_list[-1]));

    my $prev = shift @cidr_list;
    push @cidr_list, 32;
    foreach $cidr (@cidr_list) {
	my $diff = $cidr - $prev;
	my $max_list_lenght = (1 << $diff);
	$max_search += $max_list_lenght;
	print "$cidr - $prev = $diff => " . (1 << $diff) . "\tmax_search:\t$max_search\n";
	$prev = $cidr;
    }

    print "Tree depth (jump rules)   :\t $jumps\n";
    print "Leaf network max elements :\t $leaf_network_elements\n";
    print "Longest search in the tree:\t " . ($max_search - $leaf_network_elements) . "\n";
    print "Longest search in the tree:\t $max_search (incl. leaf network)\n";
    #
    # We are actually missing the length of the "root-node" chain
    # as this can get very large dependent on the first CIDR
    # and most importantly the distribution of IP-ranges used.
    #

    return $max_search;
}


sub get_chainname_base($)
{
    my $self = shift;
    my $name = $self->{'skeleton_name'} . "_" . $self->{'skeleton_type'};
    return $name;
}

sub get_chainname_skeleton($)
{
    my $self = shift;
    my $name = $self->get_chainname_base()  . "_" . "skeleton";
    return $name;
}

sub get_chainname_subnet($$$)
{
    my $self   = shift;
    my $subnet = shift;
    my $mask   = shift;
    my $name = $self->get_chainname_base() . $subnet . "_" . $mask;
    return $name;
}


# our $debug;
# #$debug = "true";
# sub iptables_command($$)
# {
#     my $self      = shift;
#     my $commands  = shift;
#     my $table     = $self->{'netfilter_table'};
#
#     my $full_command = "$iptables -t $table $commands 2>&1";
#
#     die "ERROR -- Use of obsolete function";
#
#     my $res;
#     my $status;
#     if ($debug) {
# 	print "DEBUG: $full_command\n";
# 	$status = 1;
#     } else {
# 	$res = `$full_command`;
#         #
# 	# The exit value is in the high byte of the 16-bit status word
# 	$status = $? >> 8;
#     }
#
#     if ($status != 0) {
# 	$self->{'iptables_error'} = $res;
#     } else {
# 	$self->{'iptables_result'} = $res;
#     }
#
#     if ($status == 3) {
# 	warn "[iptables_command] WARNING: Permission problems?\n";
#     }
#     return $status;
# }

sub iptables_chain_exist($$)
{
    my $self      = shift;
    my $chainname = shift;
    my $ipt       = $self->get_iptables_object();

    my $success= $ipt->is_chain("$chainname");
    #my $status = $ipt->get_exitcode();

    return $success;
}

sub iptables_chain_new($$)
{
    my $self      = shift;
    my $chainname = shift;
    my $ipt       = $self->get_iptables_object();

    #my $status = $self->iptables_command("-N $chainname");
    my $success = $ipt->create_chain("$chainname");
    return $success;
}

#
# Small helper function to return the correct
# iptables match type, that can be used in the rule.
sub match_type($)
{
    my $self = shift;
    my $match_type;

    my $type = $self->{'skeleton_type'};
    if ($type eq 'src') {
	$match_type = "-s";
    } elsif ($type eq 'dst') {
	$match_type = "-d";
    } else {
	die("${packageid}::skeleton_type not 'src' or 'dst'");
    }
    return $match_type;
}

# iptables_insert($insert_chain, $match, $target);
#
sub iptables_insert($$$)
{
    my $self         = shift;
    my $insert_chain = shift;
    my $match        = shift;
    my $target       = shift;
    my $match_type   = $self->match_type();
    my $ipt          = $self->get_iptables_object();

    my $the_match="";
    if (defined $match && $match ne "") {
	$the_match="$match_type $match";
    }
    my $success = $ipt->insert_rule("$insert_chain", "$the_match", "$target");
    return $success;
}

# iptables_append($append_chain, $match, $target);
#
sub iptables_append($$$)
{
    my $self         = shift;
    my $append_chain = shift;
    my $match        = shift;
    my $target       = shift;
    my $match_type   = $self->match_type();
    my $ipt          = $self->get_iptables_object();

    my $the_match="";
    if (defined $match && $match ne "") {
	$the_match="$match_type $match";
    }
    my $success = $ipt->append_rule("$append_chain", "$the_match", "$target");
    return $success;
}


# iptables_delete($chain, $match, $target);
#
sub iptables_delete($$$)
{
    my $self         = shift;
    my $chain        = shift;
    my $match        = shift;
    my $target       = shift;
    my $match_type   = $self->match_type();
    my $ipt          = $self->get_iptables_object();

   #my $status = $self->iptables_command("-D $chain $match_type $match -j $target");
    my $the_match="";
    if (defined $match && $match ne "") {
	$the_match="$match_type $match";
    }
    my $success = $ipt->delete_rule("$chain", "$the_match", "$target");
    return $success;
}

# iptables_commit();
#
sub iptables_commit()
{
    my $self         = shift;
    my $ipt          = $self->get_iptables_object();

    my $success = $ipt->commit();
    return $success;
}


our $algo_debug;
#$algo_debug = "true";
# insert_element($ip, $target_chain)
#
# Insert the $ip into the subnet skeleton. When matching the IP,
# jump to $target_chain.
sub insert_element($$)
{
    my $self = shift;
    my $ip   = shift;
    my $target_chain = shift;

    # Validate input parameters
    if ( ! Net::IPAddress::validaddr("$ip") ) {
	die "[insert_element] Not valid IP: $ip ... missing string quotes?\n";
    }
    if ( !$self->iptables_chain_exist("$target_chain") ) {
	warn "[insert_element] ERROR: TargetChain \"$target_chain\" does not exist\n";
    }

    # 1. Initializes
    # The initial chainname
    print "1." if ($algo_debug);
    my $POS = $self->get_chainname_skeleton;
    my $i = 0;
    #
    # Create the base chain if it don't exists.
    # - This check is removed, as it's created elsewhere.
    # if ( !$self->iptables_chain_exist("$POS") ){
    #     $self->iptables_chain_new("$POS");
    # }

    my $cidr_ref = $self->{'cidr_breaks'};
    #my $num_elem = $#{$cidr_ref};

    # 2. "Check for termination", is done simply by processing all
    #    elements in the list "cidr_breaks".
    #
    print "2." if ($algo_debug);
    # Loop over CIDR list
    foreach my $mask (@{$cidr_ref}) {
	# 3. Calculate subnet
	print "3." if ($algo_debug);
	my $SUBNET = Net::IPAddress::mask("$ip",$mask);
	#print "$ip/$mask => subnet: $SUBNET\n";
	my $chainname = $self->get_chainname_subnet($SUBNET, $mask);

	# 4. Is subnet present? => goto 6
	#    Check that $chainname exists, if it does we assume that
	#    the jump target also exists in the $POS chain.
	if ( !$self->iptables_chain_exist("$chainname") ){
	    print "5." if ($algo_debug);

	    # 5. Create subnet chain and connect to $POS chain
	    $self->iptables_chain_new($chainname);
	    $self->iptables_insert($POS, "$SUBNET/$mask", $chainname);
	}
	# 6. "Enter subnet chain"
	$POS = $chainname;
	print "6." if ($algo_debug);
    }
    # 2. "Connect TargetChain",
    #    at the end of the foreach loop we know that "bi == bn".
    print "end.\n" if ($algo_debug);
    # Extra          : need to avoid inserting if it already exists
    # Simply solution: delete and insert
    $self->iptables_delete($POS, "$ip", $target_chain);
    $self->iptables_insert($POS, "$ip", $target_chain);

}

sub get_leaf_chainname($)
{
    my $self = shift;
    my $ip   = shift;

    my $cidr_ref = $self->{'cidr_breaks'};
    #my $bottom_cidr = @{$cidr_ref}[-1];
    my $bottom_cidr = $cidr_ref->[-1];

    my $SUBNET = Net::IPAddress::mask("$ip",$bottom_cidr);
    my $chainname = $self->get_chainname_subnet($SUBNET, $bottom_cidr);

    return $chainname;
}

sub disconnect_element($$)
{
    my $self = shift;
    my $ip   = shift;
    my $target_chain = shift;

    my $leaf_chainname = $self->get_leaf_chainname("$ip");
    my $success = 0;

    # Check that the $target_chain exist before trying to
    # delete a rule refering to it... as it will fail and die!
    if ( $self->iptables_chain_exist("$target_chain") ) {
	$success = $self->iptables_delete("$leaf_chainname", "$ip", "$target_chain");
    }

    return $success;
}
# Idea:
#  'disconnect_element' does not cleanup the tree (or actually trie).
#  This could be solved by, looking at neighbors at the leaf, if no
#  neighbors is left (no rules left in the chain), we can try
#  cleaning the parent node (recurse...).



# Idea: Cleaning the tree.
#  A tree pruning or periodic cleanup, could be done by looking at
#  chains with zero "references".
#
#  ... but it probably won't happen as we do not perform inner tree
#  cleanups (we only do leaf deletes).

1;

# Usage example:
#  my $hat = IPTables::SubnetSkeleton::new(Access, src, "filter", 20, 24, 27);
#  $hat->validate_cidr_breaks();
#  $hat->insert_element($IP, $TargetChain);

__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

IPTables::SubnetSkeleton - iptables subnet based IP search tree

=head1 INTRODUCTION

SubnetSkeleton is a Perl module for building search trees for
netfilter/iptables. This is primarily to be used to cut down on
the number of lookups needed in the IPTables rule space from
O(n) to O(log n).

Initially it was written because the author had 3000+ IP addresses
and needed special treatment of each. Linear scans on 3000 addresses
are far too many to be feasible. This the following package was
developed in order to cut down on the number of lookups.

=head1 SYNOPSIS

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


=head1 ALGORITHM

 Algorithm description see:  doc/algorithm_SubnetSkeleton.apt

=head1 DEPENDENCIES

L<IPTables::libiptc>,
L<IPTables::Interface>.

=head1 AUTHORS

  Jesper Louis Andersen (jla@comx.dk) or (jlouis@mongers.org).
  Jesper Dangaard Brouer (jdb@comx.dk) or (hawk@diku.dk).

=head1 SVN revision

 $Date: 2008-09-10 19:55:59 +0200 (Wed, 10 Sep 2008) $
 $LastChangedRevision: 969 $


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2011 by Jesper Dangaard Brouer.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.


=head1 TODO

  Better documentation.

  Better descriptions on each function, describing what it does.

  Perform lenght check of the auto-generated userchain-"names".  The
  lenght of iptables userchain-"names" is restricted to 29 charaters.

=cut
