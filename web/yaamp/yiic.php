<?php

if(php_sapi_name() != "cli") return;

// Yii turns every reported PHP notice into an exception (a 500 error page).
// Don't let deprecation notices from newer PHP releases break the pool.
error_reporting(E_ALL & ~E_DEPRECATED);

require_once('serverconfig.php');
require_once('yaamp/defaultconfig.php');
require_once('yaamp/core/core.php');
require_once('yaamp/ui/lib/lib.php');

$config = require_once('yaamp/console.php');

// fix for fcgi
defined('STDIN') or define('STDIN', fopen('php://stdin', 'r'));

defined('YII_DEBUG') or define('YII_DEBUG',true);

require_once('framework'.'/yii.php');

if(isset($config))
{
	$app=Yii::createConsoleApplication($config);
	$app->commandRunner->addCommands(YII_PATH.'/cli/commands');
}
else
	$app=Yii::createConsoleApplication(array('basePath'=>dirname(__FILE__).'/cli'));

$env=@getenv('YII_CONSOLE_COMMANDS');
if(!empty($env))
	$app->commandRunner->addCommands($env);

$app->run();
