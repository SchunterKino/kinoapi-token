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
$key = base64_decode(TOKEN_KEY, true);
if (empty(TOKEN_KEY) || $key === false || empty(PASSWORD_HASH)) {
	http_response_code(400);
	exit('Script not fully setup.');
}

// We only respond to secure requests.
if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] == 'off') {
	http_response_code(400);
	exit('HTTPS is required.');
}

// Make sure we have the info we need.
if (!isset($_POST) || !isset($_POST['password']) || is_array($_POST['password'])) {
	http_response_code(400);
	exit('Invalid request.');
}

// Limit login attempts to X per minute and ban the IP if typed wrong too often.
// https://coderwall.com/p/sauviq/brute-force-protection-in-php
$apc_key = "login:{$_SERVER['REMOTE_ADDR']}";
$apc_blocked_key = "login-blocked:{$_SERVER['REMOTE_ADDR']}";
$tries = (int)apcu_fetch($apc_key);

if ($tries >= MAX_PASSWORD_TRIES) {
	http_response_code(429); // Too Many Requests
	exit("You've exceeded the number of login attempts. We've blocked IP address {$_SERVER['REMOTE_ADDR']} for a few minutes.");
}

// Authenticate the user.
if (!password_verify($_POST['password'], PASSWORD_HASH)) {
	
	// See how often this IP was blocked in the last 24 hours.
	$blocked = (int)apcu_fetch($apc_blocked_key);
	
	// Store tries for 2^(x+1) minutes: 2, 4, 8, 16, ...
	// Store the number of failed attempts longer exponentially (and block the IP longer)
	// if the IP was blocked before.
	$block_time = pow(2, $blocked + 1) * 60;
	apcu_store($apc_key, $tries + 1, $block_time);
	
	// Remember the number of times this IP was banned for 24 hours.
	if ($tries + 1 >= MAX_PASSWORD_TRIES)
		apcu_store($apc_blocked_key, $blocked + 1, 60*60*24);
	
	http_response_code(401);
	die();
} else {
	// A successful login resets the IP ban counter.
	apcu_delete($apc_key);
	apcu_delete($apc_blocked_key);
}

// Generate a signed token.
$jwt = JWT::encode($token_base, $key, SIGNING_ALGORITHM);

// Set it as a cookie on the client.
// Forget the token when the client closes the browser.
if (PHP_MAJOR_VERSION > 7 || (PHP_MAJOR_VERSION == 7 && PHP_MINOR_VERSION >= 3)) {
	// Set the SameSite cookie attribute if possible.
	$options = array('expires': 0, 'path': '/', 'domain': COOKIE_DOMAIN, 'secure': true, 'httponly': true, 'samesite': 'Strict');
	setcookie('token', $jwt, $options);
} else {
	setcookie('token', $jwt, 0, '/', COOKIE_DOMAIN, true, true);
}
echo 'OK';

//$decoded = JWT::decode($jwt, $key, array(SIGNING_ALGORITHM));
//print_r($decoded);
