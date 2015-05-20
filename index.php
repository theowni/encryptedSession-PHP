<?php

/**
 *
 *   This is very simple example of using encryptedSession class
 *
 *   You can use my example _setup script to generate own secret key 
 *   You should do it once and have only one key for one website
 *
 */

include('lib/_session.php');
include('_secret_key.php');                       # You have to generate the key once and then keep it safe in some file or database

$session = new encryptedSession($secret_key);
session_set_save_handler($session, true);
$status = $session->start();

unset($secret_key);                                # unset variable $secret_key for security
$info = '';

if($status == 'EXPIRED') 
	$info .= '#Session has expired, sorry';
else if($status == 'LOGGED')
{
	$info .= '#New session started';
	
	$_SESSION['admin'] = true;                     # You can use PHP Session normally
}
else if($status == 'CONTINUE')
	$info .= '#Session normally continued';
else
	$info .= '#Error, something went wrong';          # error



if ($_SERVER['REQUEST_METHOD'] == 'POST')
{
	if (!empty($_POST['key']) && !empty($_POST['val']))	
	{
		$key = $_POST['key'];
		$val = $_POST['val'];
		
		$_SESSION[$key] = $val; 
	}
	
	if(isset($_POST['logout']))
	{
		$session->delete();
		
		$loc = 'http://' . $_SERVER['SERVER_NAME'] . $_SERVER['REQUEST_URI'];
		header("Location: $loc");
	}
}

if(!empty($_SESSION['admin']))
	$info .= '<br/><br/><b>Welcome Admin</b>';
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>encryptedSession example</title>
</head>
<body>

<?php echo $info; ?>

<h3 style="margin:50px 0 0 0">Your ID: <?php echo session_id(); ?></h3>

<h3 style="margin:50px 0 0 0">Your data:</h3>
<div style="margin:20px 0 0 0">
<?php
	foreach($_SESSION as $key => $val)
	{
		echo $key.' = ';
		echo $val.'<br/>';
	}
?>
</div>
<h3 style="margin:50px 0 0 0">Logout at: <?php echo date("H:i:s", $_SESSION['lastActivity'] + 10*60); ?></h3>
<h3 style="margin:50px 0 0 0">Set new data:</h3>
<div style="margin:20px 0 0 10px">
<form action="index.php" method="POST">
	<input name="key" type="text" value="" />
	<input name="val" type="text" value="" />
	<input type="submit" value="go" />
</form>
</div>
<h3 style="margin:50px 0 0 0">Logout:</h3>
<div style="margin:20px 0 0 10px">
<form action="index.php" method="POST">
	<input type="hidden" name="logout" value="1" />
	<input type="submit" value="logout" />
</form>
</div>
</body>
</html>