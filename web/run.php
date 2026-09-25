<?php

if(php_sapi_name() != "cli") return;

// Yii turns every reported PHP notice into an exception (a 500 error page).
// Don't let deprecation notices from newer PHP releases break the pool.
error_reporting(E_ALL & ~E_DEPRECATED);

require_once('serverconfig.php');
require_once('yaamp/defaultconfig.php');

require_once('framework/yii.php');
require_once('yaamp/include.php');

$app = Yii::createWebApplication('yaamp/config.php');

try
{
	$app->runController($argv[1]);
}

catch(CException $e)
{
	debuglog($e, 5);

// 	$message = $e->getMessage();
// 	send_email_alert('backend', "backend error", "$message");
}


