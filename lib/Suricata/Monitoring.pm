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
		thresholds {
			'drop_per_eq'     => 'gte',
			'error_delta_eq'  => 'gte',
			'drop_per_val'    => '1',
			'error_delta_val' => '1',
		},
		max_age => 360,
		mode    => 'librenms',
	};
	bless $self;

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

	# used for check if everything is valid for threshold settings
	my $equality_values = { 'lt' => '', 'lte' => '', 'gt' => '', 'gte' => '' };
	my @equality_keys   = ( 'drop_per_eq',  'drop_d_eq',  'error_per_eq',  'error_delta_eq' );
	my @threshold_keys  = ( 'drop_per_val', 'drop_d_val', 'error_per_val', 'error_delta_val' );

	if ( defined( $args{thresholds} ) ) {

		# make sure all the equality values are valid
		foreach my $current_key (@equality_keys) {
			if ( defined( $args{thresholds}{$current_key} ) ) {
				if ( !defined( $equality_values->{ $args{thresholds}{$current_key} } ) ) {
					confess( '"' . $args{thresholds}{$current_key} . '" for a equality value' );
				}
				$self->{thresholds}{$current_key} = $args{thresholds}{$current_key};
			}
		}

		# make sure all the threshold keys are are integers
		foreach my $current_key (@threshold_keys) {
			if ( defined( $args{thresholds}{$current_key} ) ) {
				if ( $args{thresholds}{$current_key} !~ /^[0123456789]+$/ ) {
					confess( '"' . $args{thresholds}{$current_key} . '" for "' . $current_key . '" is not numeric' );
				}
				$self->{thresholds}{$current_key} = $args{thresholds}{$current_key};
			}
		}
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
	my $to_return = { instances => {}, version => 1, error => '0', errorString => '' };

	my $previous;
	my $previous_file = $self->{cache_dir} . 'stats.json';
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
					$process_it=0;

					my $new_stats={
								   packets=>$json->{stats}{capture}{kernel_packets},
								   dropped=>$json->{stats}{capture}{kernel_drops},
								   errors=>$json->{stats}{capture}{errors},
								   p_change=>0,
								   d_change=>0,
								   e_change=>0,
								   d_percent=>0,
								   e_percent=>0,
								   bytes=>$json->{stats}{decoder}{btyes},
								   dpackets=>$json->{stats}{decoder}{packets},
								   invalid=>$json->{stats}{decoder}{btyes},
								   ipv4=>$json->{stats}{decoder}{ipv4},
								   ipv6=>$json->{stats}{decoder}{ipv6},
								   udp=>$json->{stats}{decoder}{udp},
								   tcp=>$json->{stats}{decoder}{tcp},
								   avg_pkg_size=>$json->{stats}{decoder}{avg_pkg_size},
								   max_pkg_size=>$json->{stats}{decoder}{max_pkg_size},
								   flows=>$json->{stats}{app_layer}{flows},

				}
			}
		}
	}

	return $to_return;
}

sub results_to_string {
	my $self = $_[0];
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
