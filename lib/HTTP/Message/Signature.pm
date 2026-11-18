## Please see file perltidy.ERR
package HTTP::Message::Signature;

use v5.24;
use Moo;

use Carp        qw( carp croak );
use Crypt::PK::Ed25519;
use Crypt::PRNG qw(random_bytes_b64u);
use Hash::MultiValue;
use HTTP::Message;
use HTTP::Tiny;
use Hash::Ordered;
use JSON::MaybeXS qw( decode_json );
use List::Util    qw( first pairmap );
use MIME::Base64  qw( decode_base64 );
use PerlX::Maybe  qw( maybe );
use Ref::Util     qw( is_plain_hashref );
use String::Util  qw( unquote );
use Types::Common qw( Bool HashRef InstanceOf NonEmptyStr  );
use Types::URI    qw( Uri );
use URI;

use experimental qw( signatures );

use namespace::autoclean;

=head1 STATUS

This module is an experimental prototype.

The user interface is subject to change.

See also L</KNOWN ISSUES> and L</SECURITY CONSIDERATIONS>.

=cut

=attr message

This is an L<HTTP::Message> or a L<Plack::Request>.

Note that you can pass a L<PSGI> environment hash reference to the constructor.

=cut

has message => (
    is       => 'ro',
    isa      => InstanceOf [ qw/ HTTP::Message Plack::Request / ],
    required => 1,
    handles  => [qw/ as_string headers /],
);

has is_request => (
    is      => 'lazy',
    isa     => Bool,
    builder => sub($self) {
        my $message = $self->message;
        return $message->isa("HTTP::Request") || $message->isa("Plack::Request");
    },
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

has signature_input => (
    is      => 'lazy',
    isa     => InstanceOf ['Hash::MultiValue'],
    builder => sub($self) {
        my $input = $self->headers->header("signature-input");

        # TODO: use a proper HTTP Structured Field (RFC 9651) parser
        return Hash::MultiValue->new( map { split /(*nlb:=)=(*nla:=)/ } split /[;]s*/, $input );
    }
);

has signature_header => (
    is      => 'lazy',
    isa     => InstanceOf ['Hash::MultiValue'],
    builder => sub($self) {
        my $input = $self->headers->header("signature");

        # TODO: use a proper HTTP Structured Field (RFC 9651) parser
        return Hash::MultiValue->new( map { split /(*nlb:=)=(*nla:=)/ } split /[,]s*/, $input );
    },
    handles => {
        signature_tags => 'keys',
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
    isa => HashRef, # TODO make strict validation optional
    builder => sub($self) {
        return decode_json( $self->public_keys_json );
    },
);


sub verify($self, $tag = undef) {

    my $kid = unquote( $self->signature_input->{keyid} )
        or croak "not keyid was found in the signature-input";

    my $key = first { $_->{kid} eq $kid } $self->public_keys->{keys}->@*
      or croak "keyid '${kid}' was not found in the public keys";

    croak "unsupposed algorithm" unless $key->{crv} eq "Ed25519";

    my $pk = Crypt::PK::Ed25519->new();
    $pk->import_key($key);

    ($tag) = sort $self->signature_tags unless defined $tag;
    my $sig = decode_base64( $self->signature_header->{$tag} );

    my $base = $self->_generate_signature_base($tag);

    return $pk->verify_message( $sig, $base );
}

sub _generate_signature_base( $self, $tag ) {

    my @buffer;

    my $seen = Hash::Ordered->new;

    my sub _process_header_field( $field, $value ) {

        # TODO serialize line as per "component-identifier ABNF rule"
        # TODO canonicalize the field value
        my $line = sprintf( '%s: %s', lc($field), $value // "" );
        croak "component has already been added to the sginature base" if $seen->exists( lc $field );
        $seen->set( lc $field => 1 );
        push @buffer, $line;
    }

    my $input  = $self->signature_input->{$tag} or croak "signature-input tag ${tag} was not found";
    my @fields = map { unquote($_) } split / /, unquote( $input, braces => 1 );

    for my $field (@fields) {
        if ( substr( $field, 0, 1 ) eq '@' ) {
            _process_header_field( $self->_get_derived_field($field) );
        }
        else {
            _process_header_field( $field => $self->headers->header($field) );
        }
    }

    my $header = $self->headers->header("signature-input");
    croak "unexpected signature-input" unless substr( $header, 0, length($tag) + 1 ) eq "${tag}=";
    my $params = substr( $header, length($tag) + 1 );
    _process_header_field( '@signature-params' => $params );

    return join( "\n", @buffer );
}

sub _get_derived_field( $self, $field ) {

    # Note: HTTP::Message has uri_canonical but Plack::Request does not.

    state %handlers = (
        '@status'     => sub( $message, $ ) { $message->code },
        '@method'     => sub( $message, $ ) { $message->method },
        '@target-uri' => sub( $message, $ ) { $message->uri },
        '@authority'  => sub( $message, $ ) { $message->uri->authority },
        '@scheme'     => sub( $message, $ ) { $message->uri->scheme },
        '@path'       => sub( $message, $ ) { $message->uri->path },
        '@query'      => sub( $message, $ ) {
            my $query = $message->uri_canonical->query;
            if ( defined $query ) {
                return '?' . $query;
            }
            return undef;
        },
        '@query-param' => sub( $message, $param ) {
            if ( my ($name) = $param =~ /\A name = " (\w+) " \z/ax ) {

                # Note: RFC 9421 Sec 2.2.8 says named parameters with multiple values must not be included
                return $message->uri_canonical->query_param($name);
            }
        },
    );

    my ( $key, $param, @extra ) = split /;/, $field;

    croak "extra parameters in field ${field}" if @extra;

    if ( my ($quoted) = $key =~ /\A " ( \@ (?:\w+-)* \w+ ) "\z/ax ) {
        $key = $quoted;
    }

    croak "unsupported field ${field}" unless exists $handlers{$key};

    my $qfield = "\"${key}\"";
    $qfield .= ";${param}" if defined $param;

    return ( maybe $qfield => $handlers{$key}->( $self->message, $param ) );
}

sub BUILDARGS( $class, @args ) {

    my %args = @args == 1 && is_plain_hashref($args[0]) ? $args[0]->%* : @args;

    my $message = $args{message};
    if (is_plain_hashref($message)) {
        require Plack::Request;
        $args{message} = Plack::Request->new($message);

    }

    return \%args;
}

=head1 KNOWN ISSUES

=head2 Multiple Signatures

The current version of this module does not support multiple signatures.

=head1 SECURITY CONSIDERATIONS

=head2 Structured Fields

The current version of this module uses regular expressions for splitting dictionary and parameter fields,
rather than using an HTTP Structured Field (RFC 9651) parser.

=cut

1;
