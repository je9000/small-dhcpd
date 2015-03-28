use warnings;
use strict;

print "Initializing...";

my %assigned_ips;

{
 local $" = ', ';
 print "Passed args = @ARGV\n";
}

# return "10.30.2.13", "255.255.255.0", "10.30.2.40", "10.30.2.40", (60 * 60)
#             IP            Subnet          gateway        dns           lease time

sub dhcp_offer {
 my ($transaction_id, $ethernet_address, $ip_address, $gateway_ip) = @_;
 local $" = ", ";
 print scalar localtime() . " - DHCP Offer! Args-> @_ <--End\n";
 if ((defined $assigned_ips{'10.30.2.13'}) && ($assigned_ips{'10.30.2.13'} ne $ethernet_address)) { print "Declining!\n"; return; }

 $assigned_ips{'10.30.2.13'} = $ethernet_address;
 return "10.30.2.13", "255.255.255.0", "10.30.2.254", "10.30.2.40", (60 * 60);
}

sub dhcp_offer_ack {
 my ($transaction_id, $ethernet_address, $ip_address, $gateway_ip) = @_;
 local $" = ", ";
 print scalar localtime() . " - DHCP Offer Ack! Args-> @_ <--End\n";
 if ((!defined $assigned_ips{$ip_address}) || ($assigned_ips{$ip_address} ne $ethernet_address)) { print "Declining!\n"; return; }
 if ($ip_address ne "10.30.2.13") { warn "What the hell - $ethernet_address?!"; }
 
 return "10.30.2.13", "255.255.255.0", "10.30.2.254", "10.30.2.40", (60 * 60);
}

sub dhcp_inform {
 my ($transaction_id, $ethernet_address, $ip_address, $gateway_ip) = @_;
 local $" = ", ";
 print scalar localtime() . " - DHCP Inform! Args-> @_ <--End\n";
 if (!defined $assigned_ips{$ip_address}) { print "Declining!\n"; return; }
 return "10.30.2.13", "255.255.255.0", "10.30.2.254", "10.30.2.40", (60 * 60);
}

sub dhcp_release {
 my ($transaction_id, $ethernet_address, $ip_address, $gateway_ip) = @_;
 local $" = ", ";
 print scalar localtime() . " - DHCP Release! Args-> @_ <--End\n";
 delete $assigned_ips{'10.30.2.13'};
 return;
}

sub dhcp_decline {
 my ($transaction_id, $ethernet_address, $gateway_ip) = @_;
 local $" = ", ";
 delete $assigned_ips{'10.30.2.13'};
 print scalar localtime() . " - DHCP Decline! Args-> @_ <--End\n";
 return;
}

print "Done! " . (2 * 5) . "\n";

