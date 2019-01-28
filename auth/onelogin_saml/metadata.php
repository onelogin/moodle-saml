<?php

//Load Onelogin SAML libs
require_once('_toolkit_loader.php');
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Error;

try {
    //Load moodle
    require_once('../../config.php');

    $PAGE->set_url('/auth/onelogin_saml/metadata.php');
    $PAGE->set_context(context_system::instance());

    require_once('functions.php');

    $settingsInfo = auth_onelogin_saml_get_settings();


    $settings = new Settings($settingsInfo, true);
    $metadata = $settings->getSPMetadata();

    $errors = $settings->validateMetadata($metadata);
    if (empty($errors)) {
        header('Content-Type: text/xml');
        echo $metadata;
    } else {
        throw new Error(
            'Invalid SP metadata: '.implode(', ', $errors),
            Error::METADATA_SP_INVALID
        );
    }
} catch (Exception $e) {
    echo $e->getMessage();
}
