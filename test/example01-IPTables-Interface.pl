#!/usr/bin/perl -w

# Trick to alter @INC runtime
use File::Basename;
BEGIN {our $dir = dirname($0);}
use lib "$dir/../blib/lib";
use lib "$dir/../blib/arch";

use Data::Dumper;

use Log::Log4perl qw(:easy);
Log::Log4perl->easy_init($DEBUG);

use IPTables::Interface;
$table = IPTables::Interface::new('filter');

my $chain = "chainname";
$table->create_chain($chain);
$table->iptables_do_command("-A $chain", "-s 10.0.0.42", "-j ACCEPT");

# Its important to commit/push-back the changes to the kernel
$table->commit();
