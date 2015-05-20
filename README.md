Class encryptedSession PHP
==========================

Manages and keeps safer session files. Increases prevention from popular attacks like session hijacking or session fixation. 
Data is encrypted via mcrypt using algorithm MCRYPT_RIJNDAEL_256.


Usage
=====

* Include lib/_session.php into Your project
* Start session using the following code

```php
$session = new encryptedSession($secret_key);
session_set_save_handler($session, true);

$status = $session->start();
```

* You can also check status returned by *start()* method

```php
$status == 'EXPIRED'     # =>  session expired
$status == 'LOGGED'      # =>  new session started
$status == 'CONTINUE'    # =>  session continued
$status == FALSE         # =>  there was error while session_start()
```

* There is no difference in using default session and encryptedSession.

```php
$_SESSION['varName']  = $value;          # set session variable
$anotherVar = $_SESSION['varName'];      # get session variable

```


__Construct
===========

```php
encryptedSession::__construct( string $key [, string $name = 'PHP_SESSIONID' [, int $lifetime = 10 [, string $path = '' [, array $cookie = [] ]]]] );
```

* *$key* - secret key used in encryption file (recommended random 32bytes),
* *$name* - session name, (default 'PHP_SESSIONID'),
* *$lifetime* - lifetime of session (default 10min),
* *$path* - path for session files (default system path),
* *$cookie* - settings for session cookie (default [])

```php
# default session cookie params <=> $cookie = []

$default_params = array(
			'lifetime' => 0, 
			'path' => ini_get('session.cookie_path'),                  
			'domain' => ini_get('session.cookie_domain'),             
			'secure' => isset($_SERVER['HTTPS']),
			'httponly' => true
		);
```


License
=======

* https://opensource.org/licenses/MIT

Thanks
=====
* feel free to contact with me - kpranczk7@gmail.com
