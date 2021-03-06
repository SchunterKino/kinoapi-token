<?php

/**
 * Base64 encoded shared secret between this token generator and the
 * websocket server authenticating the user.
 *
 * Used to sign the JSON Web Token.
 */
define('TOKEN_KEY', '');

/**
 * Hash of the password the user has to enter to get a valid token.
 *
 * Generate using (since PHP 5.5.0)
 *   php -r 'echo password_hash("secret", PASSWORD_DEFAULT);'
 */
define('PASSWORD_HASH', '');

/**
 * How long (in seconds) should the generated token be valid?
 */
define('TOKEN_EXPIRE', 60*60*4);

/**
 * The subject to set in every token.
 */
define('TOKEN_SUBJECT', 'SchunterKinoRemote');

/**
 * The issuer of the token.
 */
define('TOKEN_ISSUER', 'http://schunterkino.de');

/**
 * The algorithm used to sign the JWT.
 * https://tools.ietf.org/html/rfc7518
 */
define('SIGNING_ALGORITHM', 'HS512');

/**
 * Only send the token cookie with connections to this domain.
 */
define('COOKIE_DOMAIN', 'remote.schunterkino.de');

/**
 * The amount of bad password attempts before the IP is banned for X minutes.
 * The number of times the IP was banned in the last 24 hours is saved.
 * The time in minutes the IP is banned after X bad attempts is then
 * determined by X = 2^(number of bans), resulting in increased time on
 * repeated failed attempts.
 */
define('MAX_PASSWORD_TRIES', 5);
