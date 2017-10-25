<?php

/**
 * Shared secret between this token generator and the
 * websocket server authenticating the user.
 *
 * Used to sign the JSON Web Token.
 */
define('TOKEN_KEY', '');

/**
 * Password the user has to enter to get a valid token.
 */
define('PASSWORD', '');

/**
 * How long (in seconds) should the generated token be valid?
 */
define('TOKEN_EXPIRE', 60*60*4);

/**
 * The subject to set in every token.
 */
define('TOKEN_SUBJECT', 'SchunterKinoRemote');

/**
 * The algorithm used to sign the JWT.
 * https://tools.ietf.org/html/rfc7518
 */
define('SIGNING_ALGORITHM', 'HS512');

/**
 * Only send the token cookie with connections to this domain.
 */
define('COOKIE_DOMAIN', 'remote.schunterkino.de');
