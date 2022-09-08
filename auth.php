<?php 

echo '<p>PHP Auth Test</p>';
require __DIR__ . '/vendor/autoload.php';
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Parser;

date_default_timezone_set('GMT');

// BEGIN CONFIGURATION

$privateKey = <<<EOD
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBell7txNDr4xYXlDeUO4ySCNRlguHisiC5nUgWDS96j4K2wPksMSA
C6RNmzaz58GPcirbCTHRkpHWhoEaTXO/U4KgBwYFK4EEACOhgYkDgYYABADijSa1
pf3o4QHKevPQ3dEcPqLQLu76K8m0fWo4dYQsaEUou8PbVlvuuMJZyuFbUPSGl+Rz
4DVE3DV1SXrCybyKYgDz2/DKYDLd8aE0YjSfQxkWmOj2Eyvktk3Yk0s/seR4ZhmH
eUhPie2ob0d7QIsC47bqnlAKllL6hPCD7QNZmt1npQ==
-----END EC PRIVATE KEY-----
EOD
;

$publicKey = <<<EOD
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBrhSkDcGyG1u3G47sfe5HW8Wx8egS
2ULxWgZ3aUAIG9p0+G+A7CNpZsrElTC9WQ4BoOFQZQgpqh+uj/Nf9yE14/EBUDoM
hhIek47tcCGBcbHCWsngMv0bSEfw+KRj3deWzopbI5xHj6DJZi5TrgFxF+3/GKMR
7aeiPBNb0lb0rfdNO5Q=
-----END PUBLIC KEY-----
EOD
;

$apiClientKey = '97ad0301-869c-4481-98b6-294b139e09ae';

// END CONFIGURATION



function createSignatureLine($method, $md5, $contentType, $timestamp, $endpoint)
{
    $line = <<<EOD
$method
$md5
$contentType
$timestamp
$endpoint
EOD;
    return $line;
}

function addPayload($token, $arg = array())
{
    foreach($arg as $index => $value) {
        $token->with($index, $value);
    }
    return $token;
}

// BEGIN EXAMPLE GET

try {
    // PREPARE LIB VARS
    $signer = new Sha512();
    $privateKey = new Key($privateKey);
    $publicKey = new Key($publicKey);
    $token = (new Builder());

    // GET TIMESTAMP FROM NOW
    $timestamp = date('D, d M Y H:i:s e');

    // CREATE THE STRING TO SIGN
    $stringToSign = createSignatureLine(
        'GET',
        '',
        '',
        $timestamp,
        '/test/16c8a1ec-8d75-47a1-b138-46746713b8d8'
    );

    // CREATE THE SIGNATURE JSON
    $signatureJson = array(
        'sub' => $apiClientKey,
        'signature' => $stringToSign
    );

    // GENERATE THE IGNED JWT
    $token = addPayload($token, $signatureJson);
    $token = $token->sign($signer, $privateKey);
    $token = $token->getToken($signer, $privateKey);
    $final = $token->__toString();

    // GENERATE THE AUTHORIZATION HEADER

    $authorizationHeader = "QIT $apiClientKey:$final";
    echo "Authorization Header:\n$final";

    $curl_h = curl_init('https://api-auth.sandbox.qitech.app/test/16c8a1ec-8d75-47a1-b138-46746713b8d8');

    curl_setopt($curl_h, CURLOPT_HTTPHEADER,
        array(
            "API-CLIENT-KEY: $apiClientKey",
            "AUTHORIZATION: $authorizationHeader",
        )
    );
    # do not output, but store to variable
    curl_setopt($curl_h, CURLOPT_RETURNTRANSFER, true);
    $response = json_decode(curl_exec($curl_h));

    // PARSE THE RESPONSE
    $encodedResponse = $response->encoded_body;

    $tokenParsed = (new Parser())->parse((string) $encodedResponse);
    $signer = new Sha512();
    $tokenPayload = $tokenParsed->getClaims();
    $tokenVerification = $tokenParsed->verify($signer, $publicKey);

} catch (Exception $e) {
    echo 'Exceção capturada: ',  $e->getMessage(), "\n";
}

$fim = 1;