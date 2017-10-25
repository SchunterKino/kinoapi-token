# kinoapi-token
Provide authentification for the API

This service validates a password sent over a HTTPS connection and generates a signed JSON Web Token. The token is sent back as a cookie which will be validated during the websocket handshake.

## Installation
This project uses PHP [Composer](https://getcomposer.org/download/) for dependency management.

To get the dependencies, run
```
composer install
```

or (for local installations)

```
php composer.phar install
```

Copy `config/config.example.php` to `config/config.php` and set the required keys.

The script only accepts requests over HTTPS.
