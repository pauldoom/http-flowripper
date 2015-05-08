#!/usr/bin/perl -wT
# $Id: http-flowripper.pl,v 1.2 2005/07/14 01:06:59 pauldoom Exp $

##
# http-flowripper.pl - Besides having the worst names of any of my scripts,
# this one takes the output of tcpflow and prints out a list of sent and
# set cookies and/or requests and responses (depending on options.)
# Data must be provided on STDIN, and be output from the tcpflow program
# using the -c option.
##

##
# Copyright (c) 2005 Paul M. Hirsch <paul@voltagenoir.org>
# All rights reserved.
#  
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
##

use strict;
use Net::Pcap;

# Comment this out if you don't want to use the optional compress/gzip decoder
# We run the decompression code unprivelaged, but still, considering the history,
# using Zlib is a security risk.  Be careful!
use Compress::Zlib;

use FileHandle;
use Getopt::Std;
use vars qw($opt_c $opt_d $opt_I $opt_E $opt_Z $opt_h $opt_V $opt_i $opt_r $opt_u $opt_g $opt_C $opt_D);

# Set to 1 if you want.  Gollers, I don't think I have any DEBUG sections
# right now.
my $DEBUG = 0;

my $usage =<<"EOU"; 
>>> HTTP Flowripper presents: Death By The Cookies <<<
Usage: $0 [-cdIEZhV] [-i interface] [-r filename] [-u UID] [-g GID] [-C /pattern/] [-D /pattern/] [expression]

-c           - Print set or returned (by browser) cookies [default action]
-d           - Print requests and responses (with headers and bodies)
-I           - Make -C and -D matches case insensitive
-E           - Exclude output cookies or data that do not match all patterns
-Z           - Try to decode gzip or compress encoded request/reponse bodies
-V, -h       - Show version and usage
-i interface - Capture packets from interface
-r filename  - Read in PCAP (tcpdump -w format) packet capture file
-u UID       - Drop privelages and run as UID (defaults to nobody)
-g GID       - Drop privelages and run as GID (defaults to nobody)
-C /pattern/ - Match cookie names (keys) using regex pattern.  Must include
               surrounding //.
-D /pattern/ - Match on requests or responses using the given regex pattern.
expression   - BPF/tcpdump style filter expression.
EOU

# Get valid options
(getopts('cdIEZhVi:r:u:g:C:D:')) || (die $usage);
my $pfilter = join(" ", @ARGV);

# I'm feeling bossy, so don't let people use the -z option when running as root
(($> == 0) && ($opt_Z)) && (die "$usage\n\nSECURITY WARNING: DUE TO HISTORIC HOLES IN COMPRESS AND GZIP, NEVER\nUSE THIS OPTION ON LIVE NETWORK DATA, OR WHEN ROOT!!\n");

if ($opt_r) {
    (-e $opt_r) || (die "FATAL: \"$opt_r\" not found: $!\n");
    (-f $opt_r) || (die "FATAL: \"$opt_r\" is not a regular file: $!\n");
} elsif (!($opt_i)) {
    die "$usage\nFATAL: You must specify a packet source!  (Interface or file)\n";
}

# Output cookies if no output selected
($opt_d) || ($opt_c = 1);

my ($src, $dst, $tsrc, $tdst) = ('','','','');
my $direct = 0;
my %csign = ('cookie' => '=',
	     'set-cookie' => '+');
my %cons = ();
my $req = '';
my ($chunk, $bug, $pbuf, $line, $cmat, $dmat);
my $sflag = 0;
my $date ='';
my $error = '';
my ($ph, $pcappid, $zh, $zpid);
my $lo = '';

if (defined($opt_C) && ($opt_C ne '')) {
    if ($opt_C =~ /^\/([^\/\n\r]+)\/$/) {
	$cmat = $1;
    } else {
	die "$usage\nFATAL: Bad cookie match pattern \"$opt_C\"\n";
    }
} else {
    # Default to matching just about anything for a cookie key
    $cmat = '[^=;]+';
}

if (defined($opt_D)  && ($opt_D ne '')) {
   if ($opt_D =~ /^\/([^\/\n\r]+)\/$/) {
	$dmat = $1;
    } else {
	die "$usage\nFATAL: Bad data match pattern \"$opt_D\"\n";
    }
} else {
    # Match anything
    $dmat = '.';
}

# Open up a PCAP worker child, and retrieve a file handle to read packets from
($ph = &OpenPcap()) || (die "FATAL: Unable to open packet capture: $!\n");

while ($line = &GetPcapLine($pcap)) {
    if ($line =~ s/^(\d{3}\.\d{3}\.\d{3}\.\d{3}\.\d{5})\-(\d{3}\.\d{3}\.\d{3}\.\d{3}\.\d{5}):\s+//) {
	$tsrc = $1;
	$tdst = $2;

	# Check for client request, or server response code at start, signifying
	# a new request or respomse in the TCP stream
	if ($line =~ /^((OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|HTTP\/\d+\.\d+) .+?)\s*$/i) {
	    $req = $1;
	    	
	    # Dump the previous connection's line
	    &PrintReq($cons{$src . $dst});
	    %{$cons{$src . $dst}} = ();

	    # Try and decide if this is a client request or server response,
	    # and set the "direction"  (which is just the text to put between
	    # the two IPs), and the order to display the IPs.
	    if ($req =~ /^HTTP\/\d+\.\d+ /) {
		# Looks like a server response, so flip things around
		$src = $tdst;
		$dst = $tsrc;
		$cons{$src . $dst}{direct} = 1;
	    } else {
		$src = $tsrc;
		$dst = $tdst;
		$cons{$src . $dst}{direct} = 0;
	    }
	    $cons{$src . $dst}{src} = $src;
	    $cons{$src . $dst}{dst} = $dst;
	    $cons{$src . $dst}{req} = $req;
	} elsif ((exists($cons{$tsrc . $tdst}{direct})) && ($cons{$tsrc . $tdst}{direct} == 0)) {
	    # Continuation of existing client request
	    $src = $tsrc;
	    $dst = $tdst;
	} elsif ((exists($cons{$tdst . $tsrc}{direct})) && ($cons{$tdst . $tsrc}{direct} == 1)) {
	    # Conitnuation of existing server response
	    $src = $tdst;
	    $dst = $tsrc;
	} else {
	    # Continuation of unknown connection, so just stop.  This is ill
	    # behaviour, but this is a test utility and not an app.
	    &PrintReq($cons{$src . $dst});
	    %{$cons{$src . $dst}} = ();
	    $src = $dst = '';
	}
    }
    ($src) && ($dst) && ($cons{$src . $dst}{data} .= $line);
    
}

# Print the last line, if there
&PrintReq($cons{$src . $dst});

exit 1;

# Drop user and group privs
sub DropPrivs {
    $) = "$gid $gid"; # EGID
    $( = $gid; # GID
    $< = $uid; # UID 
    $> = $uid; # EUID

    return 1;
}

# Open our PCAP instance in a child thread and return a file handle to read
# packets from.
sub OpenPcap {
    my ($pcapph, $pcapch);

    # Open a socket pair to communicate over
    (socketpair($pcapch, $pcapph, AF_UNIX, SOCK_STREAM, PF_UNSPEC)) || (die "FATAL: Unable to open IPC sockets: $!\n");
    
    $pcapch->autoflush(1);
    $pcapph->autoflush(1);

    # Multiply!
    if ($pcappid = fork()) {
	# We are the parent
	close $pcapph;
	return $pcapch;
    }
    
    # The PCAP worker
    my ($pcap, $error);
    if ($opt_r) {
	($pcap = Net::Pcap::open_offline($opt_r, \$error)) || (die "FATAL: Unable to open PCAP capture: $!\n");
    } else {
	
}

# Read packets out of $pcap and return a text header and followed by the data
# segment of the TCP packet.
sub GetPcapPacket {
    my $pcap = shift;
    my %head;
    my $p;

    while ($p = Net::Pcap::next($pcap, \%head)) {
	(defined($p)) || (return undef);
	
	# Make sure this is IPv4 on Ethernet
	(substr($p, 6, 2) == 0x0800) || (next);

	# q# Get timevl, source IP/port, and dest IP/port
    }

    return;
}

# Print out the request or response contained in the hash ref in $_[0]
# This thing could be broken down into more functions.
sub PrintReq {
    my $c = shift;
    ((scalar keys %{$c}) && (exists($c->{src}))) || (return 0);
    my $tcsign = '';
    my $cookie = '';
    my ($ckey, $cval) = ('', '');
    my %cookies = ();
    my $date = '';
    my $outp = '';
    my $cmatf = 0;
    my $dmatf = 0;

    # If compress/gzip decoding is requested, do so now if needed
    if ($opt_Z) {
	&DecodeData($c);
    }

    # Process the whole request
    foreach $line (split("\n", $c->{data})) {
	# Find them cookies or sets
	if ($line =~ s/^(Cookie): //i) {
	    # Set the cookie symbol for returned cookies
	    $tcsign = $csign{lc($1)};
	    
	    # Break it down
	    foreach $cookie (split(';', $line)) {
		($cookie =~ /^\s*([^=\;\s]+)\=([^\;]*?)\s*$/i) || (next);
		$ckey = $1;
		$cval = $2;
		# Skip if the cookie key does not match our filter
		($ckey =~ /$cmat/) || (next);
		# Add it to the list
		$cookies{$ckey} = "$tcsign'$cval'";
		$cmatf = 1;
	    }
	} elsif ($line =~ s/^(Set-Cookie): //i) {
	    # Set the cookie symbol for set cookies
	    $tcsign = $csign{lc($1)};
	    if (($cookie, $line) = split(';', $line, 2)) {
		# Skip if the cookie key does not match our filter
		($cookie =~ /^\s*([^=\;\s]+)\=([^\;]*?)\s*$/i) || (next);
		$ckey = $1;
		$cval = $2;
		# Skip if the cookie key does not match our filter
		($ckey =~ /$cmat/) || (next);
		# Add it to the list, with extra parameters
		$line =~ s/\s+/ /;
		$line =~ s/\s*$//;
		$line =~ s/^\s*//;
		$cookies{$ckey} = "$tcsign'$cval' ($line)";
		$cmatf = 1;
	    }
	} elsif ($line =~ /^Date: (.+?)\s*$/) {
	    # Set the date (The packet trace has nice time info, but tcpflow
	    # does not include it, so we are working with the webserver Date:
	    # headers here.)
	    $date = $1;
	}
    }
    
    # Output nothing if the data match fails (defualt is ., so that means everything)
    ($c->{data} =~ /$opt_D/) || (return 0);

    # If exlusion flag is set, exclude any output without at least one cookie match
    (($opt_E) && ($cmatf == 0)) && (return 0);

    # Print out the connection info, request/response code, and date 
    $outp .= "$c->{src} ";
    ($c->{direct} == 0) ? ($outp .= ">") : ($outp .= "<");
    $outp .= " $c->{dst}:";
    ($c->{req}) && ($outp .= " [$c->{req}]");
    ($date) && ($outp .= " ($date)");
    $outp .=  "\n";
    
    # The user asked for cookie info, so HERE
    if ($opt_c) {
	foreach $ckey (sort keys %cookies) {
	    $outp .= "\t" . $ckey . $cookies{$ckey} . ";\n";
	}
    }

    # The user asked for the raw request or response, so HERE
    if ($opt_d) {
	$outp .=  "-----\n" .  $c->{data} . "-----\n";
    }

    if ($outp eq $lo) {
	# Dupe output, so ignore
	return 1;
    } else {
	$lo = $outp;
	print STDOUT $outp, "\n";
    }

    return 1;
}

# Detect and decode encoded data.  Only compress and gzip are currently
# supported
sub DecodeData {
    my $c = shift;
    ((scalar keys %{$c}) && (exists($c->{data}))) || (return 0);
    my ($header, $type, $comdata, $uncomdata, $rem);

    # First, isolate the header
    if ($c->{data} =~ /^(.+)\r?\n\r?\n/s) {
	$header = $1;
	if ($header =~ /^Content\-Encoding\:\s*(gzip|compress)\s*$/m) {
	    $type = lc($1);
            # Looks like we have something to inflate, besides my huge
	    # ego.  We need to send the compressed data now.  
	    if ($c->{data} =~ s/(\r?\n\r?\n\s*)([^\n\r].+)(\s*)$/$1/s) {
		$comdata = $2;
		$rem = $3;

		# Decode the data and shove it back into the rest of the
		# data
		if ($type eq 'compress') { 
		    $uncomdata = &Uncompress($comdata);
		} elsif ($type eq 'gzip') {
		    $uncomdata = &Ungzip($comdata);
		} else {
		    die "FATAL: No matching decoder for \"$type\".  Hmmmm..";
		}
		$c->{data} .= $uncomdata . $rem;
	    }
	}
    }

    return 1;
}

sub Uncompress {
    my $d = shift;
    # Save a backup of input data so se can send it back on failure
    my $dbak = $d;

    # Inflate
    my $inflated = uncompress($d);
    if (defined($inflated)) {
	# Send back the decoded data
	return $inflated;
    }
    # Failed decompression, so send back original data
    print STDERR "WARNING: Compression decoder failure: $!\n";
    return $dbak;
}

sub Ungzip {
    my $d = shift;
    # Save a backup of input data so se can send it back on failure
    my $dbak = $d;

    # Inflate
    my $inflated = Compress::Zlib::memGunzip($d);
    if (defined($inflated)) {
	# Send back the decoded data
	if ($dbak eq $inflated) { die "SAME!"};
	return $inflated;
    }
    # Failed decompression, so send back original data
    print STDERR "WARNING: Compression decoder failure: $!\n";
    return $dbak;
}
