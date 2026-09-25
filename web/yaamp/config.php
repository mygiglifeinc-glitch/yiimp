<?php

// session hardening: reject unknown session ids (fixation), cookies only
if (session_status() == PHP_SESSION_NONE) {
	ini_set('session.use_strict_mode', '1');
}
$yaamp_https = !empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) != 'off';

return array(
	'name'=>YAAMP_SITE_URL,

	'defaultController'=>'site',
	'layout'=>'main',

	'basePath'=>YAAMP_HTDOCS."/yaamp",
	'extensionPath'=>YAAMP_HTDOCS.'/extensions',
	'controllerPath'=>'yaamp/modules',
	'viewPath'=>'yaamp/modules',
	'layoutPath'=>'yaamp/ui',

	'preload'=>array('log'),
	'import'=>array('application.components.*'),

	'components'=>array(

		// url() rules...
		'urlManager'=>array(
			'urlFormat'=>'path',
			'showScriptName'=>false,
			'appendParams'=>true,
			'caseSensitive'=>true,
			'rules'=>array(
				// prevent /explorer/id/<num>/p1/v1/... -> /explorer/<num>?params...
				'/explorer/<id:\d+>' => array('/explorer', 'urlFormat'=>'get'),
				'explorer/<id:\d+>' => array('explorer', 'urlFormat'=>'get'),
			),
		),

		'assetManager'=>array(
			'basePath'=>YAAMP_HTDOCS."/assets"),

		'log'=>array(
			'class'=>'CLogRouter',
			'routes'=>array(
				array(
					'class'=>'CFileLogRoute',
					'levels'=>'error, warning',
//					'levels'=>'debug, trace, error, warning',
				),
//				array(
//					'class'=>'CProfileLogRoute',
//					'report'=>'summary',
//				),
			),
		),

		'user'=>array(
			'allowAutoLogin'=>true,
			'loginUrl'=>array('site/login'),
		),

		'session'=>array(
			'cookieMode'=>'only',
			'cookieParams'=>array(
				'path'=>'/',
				'httponly'=>true,
				'secure'=>$yaamp_https,
				'samesite'=>'Lax',
			),
		),

		'db'=>array(
			'class'=>'CDbConnection',
			'connectionString'=>"mysql:host=".YAAMP_DBHOST.";dbname=".YAAMP_DBNAME,

			'username'=>YAAMP_DBUSER,
			'password'=>YAAMP_DBPASSWORD,

			'enableProfiling'=>false,
			'charset'=>'utf8',
			'schemaCachingDuration'=>3600,
		),

		'cache'=>array(
			'class'=>'CMemCache',
			'keyPrefix'=>'',
			'servers'=>array(
				array(
					'host'=>'127.0.0.1',
					'port'=> 11211,
					'weight'=> 60,
				),
			),
		),

	),


);





