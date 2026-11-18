## Please see file perltidy.ERR
package HTTP::Message::Signature;

use v5.24;
use Moo;

use Carp        qw( carp croak );
use Crypt::PRNG qw(random_bytes_b64u);
use HTTP::Headers::Fast;
use HTTP::Message;
use HTTP::Tiny;
use Hash::Ordered;
use JSON::MaybeXS qw( decode_json );
use List::Util    qw( pairmap );
use PerlX::Maybe  qw( maybe );
use String::Util  qw( unquote );
use Types::Common qw( Any ArrayRef Bool Dict InstanceOf NonEmptyStr Optional PositiveInt Slurpy  );
use Types::URI    qw( Uri );
use URI;

use experimental qw( signatures );

use namespace::autoclean;

has message => (
    is       => 'ro',
    isa      => InstanceOf ['HTTP::Message'],
    required => 1,
    handles  => [qw/ as_string headers /],
);

has is_request => (
    is      => 'lazy',
    isa     => Bool,
    builder => sub($self) { $self->message->isa("HTTP::Request") },

);

has is_response => (
    is      => 'lazy',
    isa     => Bool,
    builder => sub($self) { $self->message->isa("HTTP::Response") },

);

has user_agent => (
    is      => 'lazy',
    isa     => InstanceOf ['HTTP::Tiny'],
    builder => sub($self) {
        return HTTP::Tiny->new;
    },
);

has signature_agent_uri => (
    is      => 'lazy',
    isa     => Uri,
    coerce  => 1,
    builder => sub($self) {
        my $uri = URI->new( unquote( $self->headers->header("signature-agent") ) );
        $uri->path("/.well-known/http-message-signatures-directory");
        return $uri;
    },
);

has public_keys_json => (
    is      => 'lazy',
    isa     => NonEmptyStr,
    builder => sub($self) {

        state %types = map { $_ => 1 } qw[ application/http-message-signatures-directory+json application/json ];

        my $uri = $self->signature_agent_uri;
        croak "agent_uri should be an https URL" unless $uri->scheme eq "https";
        my $res = $self->user_agent->get("$uri");
        if ( $res->{success} && $types{ $res->{headers}{'content-type'} } ) {
            return $res->{content};
        }

        croak "error retriving ${uri}";
    }
);

has public_keys => (
    is  => 'lazy',
    isa => Dict [
        keys => ArrayRef [
            Dict [
                kid => NonEmptyStr,
                nbf => Optional [PositiveInt],
                exp => Optional [PositiveInt],
                crv => Optional [NonEmptyStr],
                Slurpy [Any],
            ]
        ],
        purpose => Optional [NonEmptyStr],
        Slurpy [Any]
    ],
    builder => sub($self) {
        return decode_json( $self->public_keys_json );
    },
);

1;
