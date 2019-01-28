<?php

// Create an __autoload function
// (can conflicts other autoloaders)
// http://php.net/manual/en/language.oop5.autoload.php

// Load composer vendor folder if any
if (file_exists('vendor/autoload.php')) {
    require 'vendor/autoload.php';
}


// Load xmlseclibs
if (!class_exists("\RobRichards\XMLSecLibs\XMLSecurityKey")) {
	$xmlseclibsSrcDir = __DIR__.'/xmlseclibs/src';

	include_once $xmlseclibsSrcDir.'/XMLSecEnc.php';
	include_once $xmlseclibsSrcDir.'/XMLSecurityDSig.php';
	include_once $xmlseclibsSrcDir.'/XMLSecurityKey.php';
	include_once $xmlseclibsSrcDir.'/Utils/XPath.php';
}

// Load php-saml
$libDir = __DIR__ . '/lib/Saml2/';

$folderInfo = scandir($libDir);

foreach ($folderInfo as $element) {
    if (is_file($libDir.$element) && (substr($element, -4) === '.php')) {
        include_once $libDir.$element;
    }
}
