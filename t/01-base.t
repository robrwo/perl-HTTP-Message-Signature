use Test2::V0 -no_srand;

use HTTP::Request;
use HTTP::Message::Signature;

subtest "base from headers" => sub {

    my $res = HTTP::Request->new(
        GET => 'http://example.com/robots.txt',
        [
            'Signature-Input' =>
'sig1=("@authority" "signature-agent");created=1794878989;expires=1794879049;keyid="VGVzdERhdGE=";alg="ed25519";tag="web-bot-auth"',
            'Signature-Agent' => '"https://example.com"',
            'Signature'       => 'sig1=:NEZha2U0RGF0YTQ=:',
        ]
    );

    ok my $sig = HTTP::Message::Signature->new( message => $res );

    ok my $base = $sig->_generate_signature_base('sig1'), '_generate_signature_base';

    is $base, "\"\@authority\": example.com
\"signature-agent\": \"https://example.com\"
\"\@signature-params\": (\"\@authority\" \"signature-agent\");created=1794878989;expires=1794879049;keyid=\"VGVzdERhdGE=\";alg=\"ed25519\";tag=\"web-bot-auth\"";

};

done_testing;
