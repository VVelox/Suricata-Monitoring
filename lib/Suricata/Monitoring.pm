package Suricata::Monitoring;

use 5.006;
use strict;
use warnings;
use JSON;
use File::Path qw(make_path);
use File::ReadBackwards;
use Carp;
use File::Slurp;
use Time::Piece;

=head1 NAME

Suricata::Monitoring - LibreNMS JSON SNMP extend and Nagios style check for Suricata stats

=head1 VERSION

Version 1.0.0

=cut

our $VERSION = '1.0.0';

=head1 SYNOPSIS

    use Suricata::Monitoring;

    my $args = {
        mode               => 'librenms',
        drop_percent_warn  => .75;
        drop_percent_crit  => 1,
        error_delta_warn   => 1,
        error_delta_crit   => 2,
        error_percent_warn => .05,
        error_percent_crit => .1,
        files=>{
               'ids'=>'/var/log/suricata/alert-ids.json',
               'foo'=>'/var/log/suricata/alert-foo.json',
               },
    };

    my $sm=Suricata::Monitoring->new( $args );
    my $returned=$sm->run;
    $sm->print;
    exit $returned->{alert};

=head1 METHODS

=head2 new

Initiate the object.

The args are taken as a hash ref. The keys are documented as below.

The only must have is 'files'.

    - mode :: Wether the print_output output should be for Nagios or LibreNMS.
      - value :: 'librenms' or 'nagios'
      - Default :: librenms

    - drop_percent_warn :: Drop percent warning threshold.
      - Default :: .75

    - drop_percent_crit :: Drop percent critical threshold.
      - Default :: 1

    - error_delta_warn :: Error delta warning threshold.
      - Default :: 1

    - error_delta_crit :: Error delta critical threshold.
      - Default :: 2

    - error_percent_warn :: Error percent warning threshold.
      - Default :: .05

    - error_percent_crit :: Error percent critical threshold.
      - Default :: .1

    - max_age :: How far back to read in seconds.
      - Default :: 360

    - files :: A hash with the keys being the instance name and the values
      being the Eve files to read.

    my $args = {
        mode               => 'librenms',
        drop_percent_warn  => .75;
        drop_percent_crit  => 1,
        error_delta_warn   => 1,
        error_delta_crit   => 2,
        error_percent_warn => .05,
        error_percent_crit => .1,
        max_age            => 360,
        files=>{
               'ids'=>'/var/log/suricata/alert-ids.json',
               'foo'=>'/var/log/suricata/alert-foo.json',
               },
    };

    my $sm=Suricata::Monitoring->new( $args );

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	# init the object
	my $self = {
		drop_percent_warn  => .75,
		drop_percent_crit  => 1,
		error_delta_warn   => 1,
		error_delta_crit   => 2,
		error_percent_warn => 0.05,
		error_percent_crit => 0.1,
		max_age            => 360,
		mode               => 'librenms',
		cache_dir          => '/var/cache/suricata-monitoring/',
	};
	bless $self;

	# reel in the numeric args
	my @num_args = (
		'drop_percent_warn',  'drop_percent_crit',  'error_delta_warn', 'error_delta_crit',
		'error_percent_warn', 'error_percent_crit', 'max_age'
	);
	for my $num_arg (@num_args) {
		if ( defined( $args{$num_arg} ) ) {
			$self->{$num_arg} = $args{$num_arg};
			if ( $args{$num_arg} !~ /[0-9\.]+/ ) {
				confess( '"' . $num_arg . '" with a value of "' . $args{$num_arg} . '" is not numeric' );
			}
		}
	}

	# get the mode and make sure it is valid
	if (
		defined( $args{mode} )
		&& (   ( $args{mode} ne 'librenms' )
			&& ( $args{mode} ne 'nagios' ) )
		)
	{
		confess( '"' . $args{mode} . '" is not a understood mode' );
	} elsif ( defined( $args{mode} ) ) {
		$self->{mode} = $args{mode};
	}

	# make sure we have files specified
	if (   ( !defined( $args{files} ) )
		|| ( !defined( keys( %{ $args{files} } ) ) ) )
	{
		confess('No files specified');
	} else {
		$self->{files} = $args{files};
	}

	# pull in cache dir location
	if ( defined( $args{cache_dir} ) ) {
		$self->{cache_dir} = $args{cache_dir};
	}

	# if the cache dir does not exist, try to create it
	if ( !-d $self->{cache_dir} ) {
		make_path( $self->{cache_dir} )
			or confess(
				'"' . $args{cache_dir} . '" does not exist or is not a directory and could not be create... ' . $@ );
	}

	return $self;
} ## end sub new

=head2 run

This runs it and collects the data. Also updates the cache.

This will return a LibreNMS style hash.

    my $returned=$sm->run;

=cut

sub run {
	my $self = $_[0];

	# this will be returned
	my $to_return = {
		data => {
			total     => {},
			instances => {},
		},
		version     => 1,
		error       => '0',
		errorString => '',
		alert       => '0',
		alertString => ''
	};

	my $previous;
	my $previous_file = $self->{cache_dir} . '/stats.json';
	if ( -f $previous_file ) {
		#
		eval {
			my $previous_raw = read_file($previous_file);
			$previous = decode_json($previous_raw);
		};
		if ($@) {
			$to_return->{error} = '1';
			$to_return->{errorString}
				= 'Failed to read previous JSON file, "' . $previous_file . '", and decode it... ' . $@;
			$self->{results} = $to_return;
			return $to_return;
		}
	} ## end if ( -f $previous_file )

	# figure out the time slot we care about
	my $from = time;
	my $till = $from - $self->{max_age};

	# process the files for each instance
	my @instances = keys( %{ $self->{files} } );
	my @alerts;
	foreach my $instance (@instances) {

		# if we found it or not
		my $found = 0;

		# ends processing for this file
		my $process_it = 1;

		# open the file for reading it backwards
		my $bw;
		eval {
			$bw = File::ReadBackwards->new( $self->{files}{$instance} )
				or die( 'Can not read "' . $self->{files}{$instance} . '"... ' . $! );
		};
		if ($@) {
			$to_return->{error} = '2';
			if ( $to_return->{errorString} ne '' ) {
				$to_return->{errorString} = $to_return->{errorString} . "\n";
			}
			$to_return->{errorString} = $to_return->{errorString} . $instance . ': ' . $@;
			$process_it = 0;
		}

		# get the first line, if possible
		my $line;
		if ($process_it) {
			$line = $bw->readline;
		}
		while ( $process_it
			&& defined($line) )
		{
			eval {
				my $json      = decode_json($line);
				my $timestamp = $json->{timestamp};
				$timestamp =~ s/\.[0-9]*//;
				my $t = Time::Piece->strptime( $timestamp, '%Y-%m-%dT%H:%M:%S%z' );

				# stop process further lines as we've hit the oldest we care about
				if ( $t->epoch <= $till ) {
					$process_it = 0;
				}

				# this is stats and we should be processing it, continue
				if ( $process_it && defined( $json->{event_type} ) && $json->{event_type} eq 'stats' ) {
					$found                                   = 1;
					$process_it                              = 0;
					$to_return->{data}{instances}{$instance} = flatten(
						$json->{stats},
						{
							HashDelimiter => '__',
						}
					);
				} ## end if ( $process_it && defined( $json->{event_type...}))
			};

			# if we did not find it, error... either Suricata is not running or stats is not output interval for
			# it is to low... needs to be under 5 minutes to function meaningfully for this
			if ( !$found && !$process_it ) {
				push( @alerts,
						  'Did not find a stats entry for instance "'
						. $instance
						. '" in "'
						. $self->{files}{$instance}
						. '" going back "'
						. $self->{max_age}
						. '" seconds' );
			} ## end if ( !$found && !$process_it )

			# get the next line
			$line = $bw->readline;
		} ## end while ( $process_it && defined($line) )

	} ## end foreach my $instance (@instances)

	# join any found alerts into the string
	$to_return->{alertString} = join( "\n", @alerts );
	$to_return->{data}{'.total'}{alert} = $to_return->{'alert'};

	# write the cache file on out
	eval {
		my $new_cache = encode_json($to_return);
		open( my $fh, '>', $previous_file );
		print $fh $new_cache . "\n";
		close($fh);
	};
	if ($@) {
		$to_return->{error}       = '1';
		$to_return->{alert}       = '3';
		$to_return->{errorString} = 'Failed to write new cache JSON file, "' . $previous_file . '".... ' . $@;

		# set the nagious style alert stuff
		$to_return->{alert} = '3';
		if ( $to_return->{alertString} eq '' ) {
			$to_return->{alertString} = $to_return->{errorString};
		} else {
			$to_return->{alertString} = $to_return->{errorString} . "\n" . $to_return->{alertString};
		}
	} ## end if ($@)

	$self->{results} = $to_return;

	return $to_return;
} ## end sub run

=head2 print_output

Prints the output.

    $sm->print_output;

=cut

sub print_output {
	my $self = $_[0];

	if ( $self->{mode} eq 'nagios' ) {
		if ( $self->{results}{alert} eq '0' ) {
			print "OK - no alerts\n";
			return;
		} elsif ( $self->{results}{alert} eq '1' ) {
			print 'WARNING - ';
		} elsif ( $self->{results}{alert} eq '2' ) {
			print 'CRITICAL - ';
		} elsif ( $self->{results}{alert} eq '3' ) {
			print 'UNKNOWN - ';
		}
		my $alerts = $self->{results}{alertString};
		chomp($alerts);
		$alerts = s/\n/\, /g;
		print $alerts. "\n";
	} else {
		print encode_json( $self->{results} ) . "\n";
	}
} ## end sub print_output

=head1 LibreNMS HASH

    + $hash{'alert'} :: Alert status.
      - 0 :: OK
      - 1 :: WARNING
      - 2 :: CRITICAL
      - 3 :: UNKNOWN
    
    + $hash{'alertString'} :: A string describing the alert. Defaults to
      '' if there is no alert.
    
    + $hash{'error'} :: A integer representing a error. '0' represents
      everything is fine.
    
    + $hash{'errorString'} :: A string description of the error.
    
    + $hash{'data'}{$instance} :: Values migrated from the
      instance. *_delta values are created via computing the difference
      from the previously saved info. *_percent is based off of the delta
      in question over the packet delta. Delta are created for packet,
      drop, ifdrop, and error. Percents are made for drop, ifdrop, and
      error.
    
    + $hash{'data'}{'.total'} :: Total values of from all the
      intances. Any percents will be recomputed.
    

    The stat keys are migrated as below.
    
    uptime           => $json->{stats}{uptime},
    packets          => $json->{stats}{capture}{kernel_packets},
    dropped          => $json->{stats}{capture}{kernel_drops},
    ifdropped        => $json->{stats}{capture}{kernel_ifdrops},
    errors           => $json->{stats}{capture}{errors},
    bytes            => $json->{stats}{decoder}{bytes},
    dec_packets      => $json->{stats}{decoder}{pkts},
    dec_invalid      => $json->{stats}{decoder}{invalid},
    dec_ipv4         => $json->{stats}{decoder}{ipv4},
    dec_ipv6         => $json->{stats}{decoder}{ipv6},
    dec_udp          => $json->{stats}{decoder}{udp},
    dec_tcp          => $json->{stats}{decoder}{tcp},
    dec_avg_pkt_size => $json->{stats}{decoder}{avg_pkt_size},
    dec_max_pkt_size => $json->{stats}{decoder}{max_pkt_size},
    dec_chdlc          => $json->{stats}{decoder}{chdlc},
    dec_ethernet       => $json->{stats}{decoder}{ethernet},
    dec_geneve         => $json->{stats}{decoder}{geneve},
    dec_ieee8021ah     => $json->{stats}{decoder}{ieee8021ah},
    dec_ipv4_in_ipv6   => $json->{stats}{decoder}{ipv6_in_ipv6},
    dec_mx_mac_addrs_d => $json->{stats}{decoder}{max_mac_addrs_dst},
    dec_mx_mac_addrs_s => $json->{stats}{decoder}{max_mac_addrs_src},
    dec_mpls           => $json->{stats}{decoder}{mpls},
    dec_ppp            => $json->{stats}{decoder}{ppp},
    dec_pppoe          => $json->{stats}{decoder}{pppoe},
    dec_raw            => $json->{stats}{decoder}{raw},
    dec_sctp           => $json->{stats}{decoder}{sctp},
    dec_sll            => $json->{stats}{decoder}{sll},
    dec_teredo         => $json->{stats}{decoder}{teredo},
    dec_too_many_layer => $json->{stats}{decoder}{too_many_layers},
    dec_vlan           => $json->{stats}{decoder}{vlan},
    dec_vlan_qinq      => $json->{stats}{decoder}{vlan_qinq},
    dec_vntag          => $json->{stats}{decoder}{vntag},
    dec_vxlan          => $json->{stats}{decoder}{vxlan},
    f_tcp              => $json->{stats}{flow}{tcp},
    f_udp              => $json->{stats}{flow}{udp},
    f_icmpv4           => $json->{stats}{flow}{icmpv4},
    f_icmpv6           => $json->{stats}{flow}{icmpv6},
    f_memuse           => $json->{stats}{flow}{memuse},
    ftp_memuse         => $json->{stats}{ftp}{memuse},
    http_memuse        => $json->{stats}{http}{memuse},
    tcp_memuse         => $json->{stats}{tcp}{memuse},
    tcp_reass_memuse   => $json->{stats}{tcp}{reassembly_memuse},
    af_*               => $json->{stats}{app_layer}{flow}{*}
    at_*               => $json->{stats}{app_layer}{tx}{*}

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-suricata-monitoring at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Suricata-Monitoring>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Suricata::Monitoring


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Suricata-Monitoring>

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Suricata-Monitoring>

=item * Search CPAN

L<https://metacpan.org/release/Suricata-Monitoring>

=back


=head * Git

L<git@github.com:VVelox/Suricata-Monitoring.git>

=item * Web

L<https://github.com/VVelox/Suricata-Monitoring>

=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Suricata::Monitoring
