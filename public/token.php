<?php
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../config/config.php';

use \Firebase\JWT\JWT;

$token_base = ['iss' => TOKEN_ISSUER,
		'iat' => time(),
		'nbf' => time(),
		// Expire in x hours.
		'exp' => time()+TOKEN_EXPIRE,
		'sub' => TOKEN_SUBJECT];

// Make sure we're configured.
if (empty(TOKEN_KEY) || empty(PASSWORD_HASH)) {
	http_response_code(400);
	die();
}

// We only respond to secure requests.
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] == 'off') {
	http_response_code(400);
	die();
}

// Make sure we have the info we need.
if (!isset($_POST) || !isset($_POST['password']) || is_array($_POST['password'])) {
	http_response_code(400);
	die();
}

// TODO: Limit login attempts to X per minute and ban the IP if typed wrong too often.

// Authenticate the user.
if (!password_verify($_POST['password'], PASSWORD_HASH)) {
	http_response_code(401);
	die();
}

// Generate a signed token.
$jwt = JWT::encode($token_base, TOKEN_KEY, SIGNING_ALGORITHM);

// Set it as a cookie on the client.
// Forget the token when the client closes the browser.
setcookie('token', $jwt, 0, '/', COOKIE_DOMAIN, true);
echo 'OK';

//$decoded = JWT::decode($jwt, TOKEN_KEY, array(SIGNING_ALGORITHM));
//print_r($decoded);
