#!/usr/local/cpanel/3rdparty/bin/perl
# Compare httpupdate mirrors

use strict;
use warnings;

use Digest::SHA;
use Net::DNS;
use LWP::UserAgent;

exit script(@ARGV) unless caller;

sub mirrors_in_rotation {
    my ($ua) = @_;
    my $url  = "http://" . mirror_name_for(0) . "/mirror_addr_list";
    my $resp = $ua->get($url);
    my $data = $resp->content;

    return grep { /^\d+\.\d+\.\d+\.\d+$/ } split /\n/, $data;
}

sub ips_for {
    my ($name) = @_;

    my $res   = Net::DNS::Resolver->new;
    my $reply = $res->search($name);
    my @addresses;

    if ($reply) {
        foreach my $rr ( $reply->answer ) {
            push @addresses, $rr->address if $rr->type eq 'A';
        }
    }
    return @addresses;
}

sub hostname_for {
    my ($mirror) = @_;
    return "httpupdate$mirror.cpanel.net";
}

sub mirror_name_for {
    my ($mirror) = @_;
    return hostname_for($mirror) . ( $mirror ? '' : ':81' );
}

sub mirror_value {
    my ( $ua, $mirror, $path ) = @_;

    my $hostname    = hostname_for($mirror);
    my $mirror_name = mirror_name_for($mirror);
    my ($ip)        = ips_for($hostname);

    return if $mirror && !$ip;

    my $sha384 = Digest::SHA->new(384);
    my $resp   = $ua->get(
        "http://$mirror_name$path",
        ':content_cb' => sub {
            $sha384->add( $_[0] );
        }
    );
    my $digest = $sha384->hexdigest;

    return {
        name     => $hostname,
        code     => $resp->code,
        digest   => $digest,
        string   => $resp->code . ": " . $digest,
        mirror   => $mirror,
        ip       => $ip,
        shunting => ( $resp->status_line =~ /Connection refused/ ) ? 1 : 0,
        timeout  => ( $resp->status_line =~ /timeout/ ) ? 1 : 0,
    };
}

sub note_mirror {
    my ( $value, $expected ) = @_;

    my $message;
    if ( !$value->{in_rotation} ) {
        $message = 'not in rotation';
    }
    elsif ( $value->{shunting} ) {
        $message = 'request shunted';
    }
    elsif ( $value->{timeout} ) {
        $message = 'timed out';
    }
    else {
        $message = $value->{string} eq $expected->{string} ? 'ok' : 'BAD';
    }

    printf "httpupdate%-3d : %-15s : %s (%s)\n", $value->{mirror}, $value->{ip}, $value->{string}, $message;
}

sub script {
    my $url = shift or die "Need a URL to check.\n";

    $url =~ s{^http://httpupdate.cpanel.net}{};

    my $ua = LWP::UserAgent->new;
    $ua->timeout(5);

    my %in_rotation = map { $_ => 1 } mirrors_in_rotation($ua);

    my $standard = mirror_value( $ua, 0, $url );
    $standard->{in_rotation} = 1;

    note_mirror( $standard, $standard );
    print "\n";

    foreach my $mirror ( 1 .. 199 ) {
        my $value = mirror_value( $ua, $mirror, $url );
        next unless defined $value;
        $value->{in_rotation} = $in_rotation{ $value->{ip} };
        note_mirror( $value, $standard );
    }
}