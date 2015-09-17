<?php
try {
	//Load moodle
	require_once('../../config.php');

	//Load Onelogin SAML libs
	require_once '_toolkit_loader.php';

	require_once('functions.php');

	$settingsInfo = auth_onelogin_saml_get_settings();


	$settings = new Onelogin_Saml2_Settings($settingsInfo, true);
	$metadata = $settings->getSPMetadata();

	$errors = $settings->validateMetadata($metadata);
	if (empty($errors)) {
		header('Content-Type: text/xml');
		echo $metadata;
	} else {
		throw new OneLogin_Saml2_Error(
			'Invalid SP metadata: '.implode(', ', $errors),
			OneLogin_Saml2_Error::METADATA_SP_INVALID
		);
	}	
} catch (Exception $e) {
	echo $e->getMessage();
}

