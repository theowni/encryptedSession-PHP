<?php

/**
 *
 *   This is an example function
 *
 *
 *   Generates _secret_key.php file with  $secret_key inside
 *   It is necessary for the proper work of the class
 *
 *   Run it just once
 *
 */

function setupEncryption($key = '')
{
	if(empty($key))
		$key = bin2hex(openssl_random_pseudo_bytes(32));   # 32 bytes gives us 256bits $secret_key
	
	$file = '_secret_key.php';
	$data = '<?php 
		$secret_key = "'.$key.'"; 
		$secret_key = pack("H*", $secret_key); 
	?>';
	
	return file_put_contents($file, $data) === false ? false : true;
}

if(setupEncryption())
	echo "Secret key generated successfully";
else
	echo "Something went wrong, the file wasn't created";

?>