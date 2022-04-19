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

Suricata::Monitoring - The great new Suricata::Monitoring!

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Suricata::Monitoring;

    my $foo = Suricata::Monitoring->new();
    ...

=head1 METHODS

=head2 new

=cut

sub new {
	my %args;
	if ( defined( $_[1] ) ) {
		%args = %{ $_[1] };
	}

	# init the object
	my $self = {
		'drop_percent_warn'  => '.75',
		'drop_percent_crit'  => '1',
		'error_delta_warn'   => '1',
		'error_delta_crit'   => '2',
		'error_percent_warn' => '0.05',
		'error_percent_crit' => '0.1',
		max_age              => 360,
		mode                 => 'librenms',
	};
	bless $self;

	# reel in the threshold values
	my @thresholds = (
		'drop_percent_warn',  'drop_percent_crit', 'error_delta_warn', 'error_delta_crit',
		'error_percent_warn', 'error_percent_crit'
	);
	for my $threshold (@thresholds) {
		if ( defined( $args{$threshold} ) ) {
			$self->{$threshold} = $args{$threshold};
			if ( $args{$threshold} !~ /[0-9\.]+/ ) {
				confess( '"' . $threshold . '" with a value of "' . $args{$threshold} . '" is not numeric' );
			}
		}
	}

	# get the mode and make sure it is valid
	if (
		defined( $args{mode} )
		&& (   ( $args{mode} ne 'librenms' )
			|| ( $args{mode} ne 'nagios' ) )
		)
	{
		confess( '"' . $args{mode} . '" is not a understood mode' );
	}
	elsif ( defined( $args{mode} ) ) {
		$self->{mode} = $args{mode};
	}

	# make sure we have files specified
	if (   ( !defined( $args{files} ) )
		|| ( !defined( keys( %{ $args{files} } ) ) ) )
	{
		confess('No files specified');
	}
	else {
		$self->{files} = $args{files};
	}

	# pull in cache dir location
	if ( !defined( $args{cache_dir} ) ) {
		$args{cache_dir} = '/var/cache/suricata-monitoring/';
	}
	$self->{cache_dir} = $args{cache_dir};

	# if the cache dir does not exist, try to create it
	if ( !-d $self->{cache_dir} ) {
		make_path( $self->{cache_dir} )
			or confess(
			'"' . $args{cache_dir} . '" does not exist or is not a directory and could not be create... ' . $@ );
	}

	return $self;
}

=head2 run

This runs it and collects the data.

The defults value is a LibreNMS JSON style hash.

=cut

sub run {
	my $self = $_[0];

	# this will be returned
	my $to_return = { data => {}, version => 1, error => '0', errorString => '', alert => '0', alertString => '' };

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
	}

	# figure out the time slot we care about
	my $from = time;
	my $till = $from - $self->{max_age};

	# process the files for each instance
	my @instances = keys( %{ $self->{files} } );
	my @alerts;
	foreach my $instance (@instances) {

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
		}

		#
		my $process_it = 1;
		my $line       = bw->readline;
		my $found;
		while ( $process_it
			&& defined($line) )
		{
			eval {
				my $json      = decode_json($line);
				my $timestamp = $json->{timestamp};
				$timestamp =~ s/\..*$//;
				my $t = Time::Piece->strptime( $timestamp, '%Y-%m-%dT%H:%M:%S' );

				# stop process further lines as we've hit the oldest we care about
				if ( $t->epoch < $till ) {
					$process_it = 0;
				}

				# we found the entry we are looking for if
				# this matches, so process it
				if ( defined( $json->{event_type} )
					&& $json->{event_type} eq 'stats' )
				{
					# we can stop processing now as this is what we were looking for
					$process_it = 0;

					# holds the found new alerts
					my @new_alerts;

					my $new_stats = {
						uptime           => $json->{stats}{uptime},
						packets          => $json->{stats}{capture}{kernel_packets},
						dropped          => $json->{stats}{capture}{kernel_drops},
						errors           => $json->{stats}{capture}{errors},
						packet_delta     => 0,
						drop_delta       => 0,
						error_delta      => 0,
						drop_percent     => 0,
						error_percent    => 0,
						bytes            => $json->{stats}{decoder}{btyes},
						dec_packets      => $json->{stats}{decoder}{packets},
						dec_invalid      => $json->{stats}{decoder}{btyes},
						dec_ipv4         => $json->{stats}{decoder}{ipv4},
						dec_ipv6         => $json->{stats}{decoder}{ipv6},
						dec_udp          => $json->{stats}{decoder}{udp},
						dec_tcp          => $json->{stats}{decoder}{tcp},
						dec_avg_pkg_size => $json->{stats}{decoder}{avg_pkg_size},
						dec_max_pkg_size => $json->{stats}{decoder}{max_pkg_size},
						f_tcp            => $json->{stats}{flow}{tcp},
						f_udp            => $json->{stats}{flow}{udp},
						f_icmpv4         => $json->{stats}{flow}{icmpv4},
						f_icmpv6         => $json->{stats}{flow}{icmpv6},
						f_memuse         => $json->{stats}{flow}{memuse},
						ftp_memuse       => $json->{stats}{ftp}{memuse},
						http_memuse      => $json->{stats}{http}{memuse},
						tcp_memuse       => $json->{stats}{tcp}{memuse},
						tcp_reass_memuse => $json->{stats}{tcp}{reassembly_memuse},
						alert            => 0,
						alert_string     => '',
					};
					foreach my $flow_key ( keys( %{ $json->{stats}{app_layer}{flows} } ) ) {
						$new_stats->{ 'af_' . $flow_key } = $json->{stats}{app_layer}{flows}{$flow_key};
					}
					foreach my $tx_key ( keys( %{ $json->{stats}{app_layer}{tx} } ) ) {
						$new_stats->{ 'at_' . $tx_key } = $json->{stats}{app_layer}{flows}{$tx_key};
					}

					# begin handling this if we have previous values
					if (   defined($previous)
						&& defined( $previous->{data}{$instance} )
						&& defined( $previous->{data}{$instance}{packets} )
						&& defined( $previous->{data}{$instance}{bytes} )
						&& defined( $previous->{data}{$instance}{dropped} )
						&& defined( $previous->{data}{$instance}{error} ) )
					{
						# find the change for packet count
						if ( $new_stats->{packets} < $previous->{data}{$instance}{packets} ) {
							$new_stats->{packet_delta} = $new_stats->{packets};
						}
						else {
							$new_stats->{packet_delta} = $new_stats->{packets} - $previous->{data}{$instance}{packets};
						}

						# find the change for drop count
						if ( $new_stats->{dropped} < $previous->{data}{$instance}{dropped} ) {
							$new_stats->{drop_delta} = $new_stats->{dropped};
						}
						else {
							$new_stats->{drop_delta} = $new_stats->{dropped} - $previous->{data}{$instance}{dropped};
						}

						# find the change for errors count
						if ( $new_stats->{errors} < $previous->{data}{$instance}{errors} ) {
							$new_stats->{error_delta} = $new_stats->{errors};
						}
						else {
							$new_stats->{error_delta} = $new_stats->{errors} - $previous->{data}{$instance}{errors};
						}

						# find the percent of dropped
						if ( $new_stats->{drop_delta} != 0 ) {
							$new_stats->{drop_percent}
								= ( $new_stats->{drop_delta} / $new_stats->{packet_delta} ) * 100;
							$new_stats->{drop_percent} = sprintf( '%0.5f', $new_stats->{drop_percent} );
						}

						# find the percent of errored
						if ( $new_stats->{error_delta} != 0 ) {
							$new_stats->{error_percent}
								= ( $new_stats->{error_delta} / $new_stats->{packet_delta} ) * 100;
							$new_stats->{error_percent} = sprintf( '%0.5f', $new_stats->{error_percent} );
						}

						# check for drop delta alerts
						if (   $new_stats->{drop_delta} >= $self->{drop_delta_warn}
							&& $new_stats->{drop_delta} < $self->{drop_delta_crit} )
						{
							$new_stats->{alert} = 1;
							push( @new_alerts,
									  $instance
									. ' drop_delta warning '
									. $new_stats->{drop_delta} . ' >= '
									. $self->{drop_delta_warn} );
						}
						if ( $new_stats->{drop_delta} >= $self->{drop_delta_crit} ) {
							$new_stats->{alert} = 2;
							push( @new_alerts,
									  $instance
									. ' drop_delta critical '
									. $new_stats->{drop_delta} . ' >= '
									. $self->{drop_delta_crit} );
						}

						# check for drop percent alerts
						if (   $new_stats->{drop_percent} >= $self->{drop_percent_warn}
							&& $new_stats->{drop_percent} < $self->{drop_percent_crit} )
						{
							$new_stats->{alert} = 1;
							push( @new_alerts,
									  $instance
									. ' drop_percent warning '
									. $new_stats->{drop_percent} . ' >= '
									. $self->{drop_percent_warn} );
						}
						if ( $new_stats->{drop_percent} >= $self->{drop_percent_crit} ) {
							$new_stats->{alert} = 2;
							push( @new_alerts,
									  $instance
									. ' drop_percent critical '
									. $new_stats->{drop_percent} . ' >= '
									. $self->{drop_percent_crit} );
						}

						# check for error delta alerts
						if (   $new_stats->{error_delta} >= $self->{error_delta_warn}
							&& $new_stats->{error_delta} < $self->{error_delta_crit} )
						{
							$new_stats->{alert} = 1;
							push( @new_alerts,
									  $instance
									. ' error_delta warning '
									. $new_stats->{error_delta} . ' >= '
									. $self->{error_delta_warn} );
						}
						if ( $new_stats->{error_delta} >= $self->{error_delta_crit} ) {
							$new_stats->{alert} = 2;
							push( @new_alerts,
									  $instance
									. ' error_delta critical '
									. $new_stats->{error_delta} . ' >= '
									. $self->{error_delta_crit} );
						}

						# check for drop percent alerts
						if (   $new_stats->{error_percent} >= $self->{error_percent_warn}
							&& $new_stats->{error_percent} < $self->{error_percent_crit} )
						{
							$new_stats->{alert} = 1;
							push( @new_alerts,
									  $instance
									. ' error_percent warning '
									. $new_stats->{error_percent} . ' >= '
									. $self->{error_percent_warn} );
						}
						if ( $new_stats->{error_percent} >= $self->{error_percent_crit} ) {
							$new_stats->{alert} = 2;
							push( @new_alerts,
									  $instance
									. ' error_percent critical '
									. $new_stats->{error_percent} . ' >= '
									. $self->{error_percent_crit} );
						}

						# check for alert status
						if ( $new_stats->{alert} > $to_return->{alert} ) {
							$to_return->{alert}       = $new_stats->{alert};
							$new_stats->{alertString} = join( "\n", @new_alerts );
							push( @alerts, @new_alerts );
						}
					}

					$to_return->{data}{$instance} = $new_stats;
				}

			};
		}

	}

	# join any found alerts into the string
	$to_return->{alertsString} = join( "\n", @alerts );

	# write the cache file on out
	eval {
		my $new_cache = encode_json($to_return);
		open( my $fh, '>', $previous_file );
		print $fh $new_cache;
		close($fh);
	};
	if ($@) {
		$to_return->{error}       = '1';
		$to_return->{errorString} = 'Failed to write new cache JSON file, "' . $previous_file . '".... ' . $@;
		$self->{results}          = $to_return;
	}

	return $to_return;
}

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


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2022 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The Artistic License 2.0 (GPL Compatible)


=cut

1;    # End of Suricata::Monitoring