package HTTP::Message::Signature;

# ABSTRACT: Verify HTTP Message Signatures (RFC 9421)

use v5.24;
use Moo;

use Carp qw( carp croak );
use Crypt::PK::Ed25519;
use Hash::MultiValue;
use HTTP::Message;
use HTTP::Tiny;
use Hash::Ordered;
use JSON::MaybeXS qw( decode_json );
use List::Util    qw( first pairmap );
use MIME::Base64  qw( decode_base64 );
use PerlX::Maybe  qw( maybe );
use Ref::Util     qw( is_plain_hashref );
use String::Util  qw( trim unquote );
use Syntax::Keyword::Match;
use Syntax::Operator::Equ;
use Types::Common qw( Bool HashRef InstanceOf NonEmptyStr  );
use Types::URI    qw( Uri );
use URI;

use experimental qw( signatures );

use namespace::autoclean;

our $VERSION = 'v0.0.1';

=head1 SYNOPSIS

    use HTTP::Message::Signature;

    try {

        my $sig = HTTP::Message::Signature->new(
            message     => $request,         # HTTP::Request, Plack::Request or PSGI env hash
            require_tag => 'web-bot-auth',
        );

        $sig->is_expired and die "expired signature";

        $sig->verify or die "bad signature";

    }
    catch ($e) {

        ...

    }

=head1 STATUS

This module is an experimental prototype.

The user interface is subject to change.

See also L</KNOWN ISSUES> and L</SECURITY CONSIDERATIONS>.

=head1 DESCRIPTION

This module supports verifying HTTP Message Signatures (RFC 9421), notably those used for Web Bot Authentication.

=cut

=attr message

This is an L<HTTP::Message> or a L<Plack::Request>.

Note that you can pass a L<PSGI> environment hash reference to the constructor.

This is required.

=cut

has message => (
    is       => 'ro',
    isa      => InstanceOf [qw/ HTTP::Message Plack::Request /],
    required => 1,
    handles  => [qw/ as_string headers /],
);

=attr is_request

True if L</message> is a request.

=cut

has is_request => (
    is      => 'lazy',
    isa     => Bool,
    builder => sub($self) {
        my $message = $self->message;
        return $message->isa("HTTP::Request") || $message->isa("Plack::Request");
    },
    init_arg => undef,
);

=attr is_response

True if L</message> is a response.

=cut

has is_response => (
    is      => 'lazy',
    isa     => Bool,
    builder => sub($self) { $self->message->isa("HTTP::Response") },
    init_arg => undef,
);

=attr user_agent

The user agent used for requesting keys.

This is a L<HTTP::Tiny> object.

=cut

has user_agent => (
    is      => 'lazy',
    isa     => InstanceOf ['HTTP::Tiny'],
    builder => sub($self) {
        return HTTP::Tiny->new;
    },
);

=attr signature_agent

This is the signature agent from the C<Signature-Agent> header.

This should be a base URL but the actual value may be quoted.
Some agents may send a full URL.

=cut

has signature_agent => (
    is      => 'lazy',
    isa     => NonEmptyStr,
    builder => sub($self) {
        my $agent = join(",", $self->headers->header("signature-agent") );
        if ( $agent =~ /\A \w+ = /ax ) {
            my ($key) = $self->headers->header("signature-agent-key") || $self->signature_labels;
            my $agents = $self->_parse_dict( ',', $agent );
            $agent = $agents->{ unquote($key) };
        }
        return $agent;
    }
);

=attr signature_agent_uri

This is the URI for the L</signature_agent> JWT key.

=cut

has signature_agent_uri => (
    is      => 'lazy',
    isa     => Uri,
    coerce  => 1,
    builder => sub($self) {
        my $uri = URI->new( unquote( $self->signature_agent ) );
        carp "signature-agent header contains a full URL" if $uri->path && $uri->path ne "/";
        $uri->path("/.well-known/http-message-signatures-directory");
        return $uri;
    },
);

=attr signature_input

This is the C<Signature-Input> header, parsed into a L<Hash::MultiValue> object.

=attr signature_labels

This is an array of the labels from the L</signature_input>.

=cut

has signature_input => (
    is      => 'lazy',
    isa     => InstanceOf ['Hash::MultiValue'],
    builder => sub($self) {
        my @input = $self->headers->header("signature-input");
        return $self->_parse_dict( ';', join( ';', @input ) );
    },
    handles => {
        signature_labels => 'keys',
    },
);

=attr signature_header

This is the C<Signature> header, parsed into a L<Hash::MultiValue> object, where the keys are labels.

=cut

has signature_header => (
    is      => 'lazy',
    isa     => InstanceOf ['Hash::MultiValue'],
    builder => sub($self) {
        my @input = $self->headers->header("signature");
        return $self->_parse_dict( ',', join( ',', @input ) );
    },
);

=attr public_keys_json

This is the raw JSON of the L</public_keys>.

The keys will be fetched from L</signature_agent_uri>.

Cached keys should be saved here instead of L</public_keys>.

=cut

has public_keys_json => (
    is      => 'lazy',
    isa     => NonEmptyStr,
    builder => sub($self) {

        # TODO: add support for caching keys by URL

        state %types = map { $_ => 1 } qw[ application/http-message-signatures-directory+json application/json ];

        my $uri = $self->signature_agent_uri;
        croak "agent_uri should be an https URL" unless $uri->scheme eq "https";
        my $res =
          $self->user_agent->get( "$uri", { headers => { 'Accept' => join( ",", keys %types ) } } );
        if ( $res->{success} && $types{ $res->{headers}{'content-type'} } ) {
            return $res->{content};
        }

        croak "error retrieving ${uri}";
    }
);

=attr public_keys

This is the parsed L</public_keys_json>.

=cut

has public_keys => (
    is      => 'lazy',
    isa     => HashRef,       # TODO make strict validation optional
    builder => sub($self) {
        return decode_json( $self->public_keys_json );
    },
);

=attr require_tag

When set, the L</verify> method requires the tag in the L</signature_input> header to be that value.

Set this to "web-bot-auth" to verify bots.

=cut

has require_tag => (
    is        => 'ro',
    isa       => NonEmptyStr,
    predicate => 1,
);

=method is_expired

Returns true if the signature is expired.

This can be checked before verification to avoid the work of checking a signature.

=cut

sub is_expired($self) {
    my $expires = $self->signature_input->{expires} or return undef;
    return time > $expires;
}

=method verify

  $sig->verify( $label ) or die "Signature ${label} is not verified";

Returns true if the signature was verified.

The C<$label> defaults to the first L</signature_labels> if omitted.

=cut

sub verify( $self, $label = undef ) {

    if ( $self->has_require_tag ) {
        my $tag = $self->require_tag;
        croak "tag is not '${tag}'" unless unquote( $self->signature_input->{tag} ) equ $tag;
    }

    my $kid = unquote( $self->signature_input->{keyid} )
      or croak "not keyid was found in the signature-input";

    # TODO: add support for looking up keys from a cache based on agent URL and key id.

    my $key = first { $_->{kid} equ $kid } $self->public_keys->{keys}->@*
      or croak "keyid '${kid}' was not found in the public keys";

    croak "unsupposed algorithm" unless $key->{crv} equ "Ed25519";

    my $pk = Crypt::PK::Ed25519->new();
    $pk->import_key($key);

    ($label) = $self->signature_labels unless defined $label;
    my $sig = decode_base64( $self->signature_header->{$label} );

    my $base = $self->_generate_signature_base($label);

    return $pk->verify_message( $sig, $base );
}

sub _generate_signature_base( $self, $label ) {

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

    my $input = $self->signature_input->{$label} or croak "signature-input label ${label} was not found";

    my @fields = split / /, unquote( $input, braces => 1 );

    for my $field (@fields) {
        if ( $field =~ /\A \"? \@/ax ) {
            _process_header_field( $self->_get_derived_field($field) );
        }
        else {

            my $value;

            my ( $key, $param ) = _structured_split( ';', $field );

            my $ufield = unquote( $param ? $key : $field );

            my $header = $self->headers->header($ufield);

            if ($param) {
                my ( $name, $key ) = _structured_split( '=', $param );
                my $hash = $self->_parse_dict( ";", $header );
                $value = $hash->{ unquote($key) };
                _process_header_field( $field => $value );
            }
            else {
                $value = $header;
                $field = unquote($field);
                _process_header_field( "\"${field}\"" => $value );
            }

        }
    }

    my $header = $self->headers->header("signature-input");
    croak "unexpected signature-input" unless substr( $header, 0, length($label) + 1 ) eq "${label}=";
    my $params = substr( $header, length($label) + 1 );
    _process_header_field( '"@signature-params"' => $params );

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
            if ( my ($name) = $param =~ /\A name = " ((?:\w+-)*\w+) " \z/ax ) {

                # Note: RFC 9421 Sec 2.2.8 says named parameters with multiple values must not be included
                return $message->uri_canonical->query_param($name);
            }
        },
    );

    my ( $key, $param, @extra ) = _structured_split( ';', $field );

    croak "extra parameters in field ${field}" if @extra;

    if ( my ($quoted) = $key =~ /\A " ( \@ (?:\w+-)* \w+ ) "\z/ax ) {
        $key = $quoted;
    }

    croak "unsupported field ${field}" unless exists $handlers{$key};

    my $qfield = "\"${key}\"";
    $qfield .= ";${param}" if defined $param;

    return ( maybe $qfield => $handlers{$key}->( $self->message, $param ) );
}

sub _parse_dict( $self, $on, $input ) {
    return Hash::MultiValue->new( map { _structured_split( '=', $_ ) } _structured_split( $on, $input ) );
}

use constant DQUOTE      => "\"";
use constant ESCAPE      => "\\";
use constant INNER_START => '(';
use constant INNER_END   => ')';

sub _structured_split( $on, $input ) {

    my @res;
    my @ctx;

    my $i = 0;

    while ( $i < length($input) ) {

        my $char = substr( $input, $i, 1 );
        match( $char : equ ) {

            case (ESCAPE) {
                my $next = substr( $input, $i + 1, 1 );
                unless ( $next equ ESCAPE || $next equ DQUOTE ) {
                    $i += 2;
                    next;
                }
                croak "invalid character after backslash";
            }

            case (INNER_START) {
                unless ( $ctx[-1] equ DQUOTE ) {
                    push @ctx, INNER_END;
                }
            }

            case (DQUOTE) {
                if ( $ctx[-1] equ DQUOTE ) {
                    pop @ctx;
                }
                else {
                    push @ctx, DQUOTE;
                }
            }

            case (INNER_END) {

                if ( $ctx[-1] equ INNER_END ) {
                    pop @ctx;
                }
                elsif ( !( $ctx[-1] equ DQUOTE ) ) {
                    croak "unbalanced bracket";
                }
            }

            case ($on) {

                unless ( $ctx[-1] ) {
                    push @res, trim( substr( $input, 0, $i ) );
                    $input = substr( $input, $i + 1 );
                    $i     = 0;
                    next;
                }
            }

        }

        $i++;
    }

    push @res, trim($input) unless $input equ "";

    return @res;
}

sub BUILDARGS( $class, @args ) {

    my %args = @args == 1 && is_plain_hashref( $args[0] ) ? $args[0]->%* : @args;

    my $message = $args{message};
    if ( is_plain_hashref($message) ) {
        require Plack::Request;
        $args{message} = Plack::Request->new($message);

    }

    return \%args;
}

=head1 KNOWN ISSUES

=head2 Signature Algorithms

The current version only supports the "Ed25519" algorithm.

=head2 Missing Signature-Agent headers

The current version does not support caching keys.

=head2 Multiple Signatures

The current version of this module does not support multiple signatures.

=head1 SECURITY CONSIDERATIONS

=head2 Structured Fields

The current version of this module uses regular expressions for splitting dictionary and parameter fields,
rather than using an HTTP Structured Field (RFC 9651) parser.

=head2 Trusted Agents

Your application should use an allowed list of trusted agents, rather than attempt to verify arbitrary requests.

=head1 SEE ALSO

L<Web Bot Auth|https://datatracker.ietf.org/wg/webbotauth/about/>

L<HTTP Message Signatures for automated traffic|https://github.com/webbotauth/draft-ietf-webbotauth-httpsig-protocol/>

L<RFC 7517: JSON Web Key (JWK)|https://www.rfc-editor.org/info/rfc7517>

L<RFC 9421: HTTP Message Signatures|https://www.rfc-editor.org/info/rfc9421>

L<RFC 9651: Structured Field Values for HTTP|https://www.rfc-editor.org/info/rfc9651>

=cut

1;
