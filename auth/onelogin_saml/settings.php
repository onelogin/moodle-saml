<?php
/* * * * * * * * * *  The OneLogin SAML authentication module for Moodle  * * * * * * * * *
 * 
 * settings.php - code for reconfiguring this module from within the Admin's GUI
 * 
 * @originalauthor OneLogin, Inc
 * @author Harrison Horowitz, Sixto Martin
 * @version 2.8.0
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package auth_onelogin_saml
 * @requires XMLSecLibs v3.0.4
 * @requires php-saml v3.3.1
 * @copyright 2011-2019 OneLogin.com
 * 
 * @description 
 * Connects to Moodle, builds the configuration, discovers SAML status, and handles the login process accordingly.
 * 
 * Security Assertion Markup Language (SAML) is a standard for logging users into applications based 
 * on their session in another context. This has significant advantages over logging in using a 
 * username/password: no need to type in credentials, no need to remember and renew password, no weak 
 * passwords etc.
 * 
 * Most companies already know the identity of users because they are logged into their Active Directory 
 * domain or intranet. It is natural to use this information to log users into other applications as well 
 * such as web-based application, and one of the more elegant ways of doing this by using SAML.
 * 
 * SAML is very powerful and flexible, but the specification can be quite a handful. Now OneLogin is 
 * releasing this SAML toolkit for your Moodle application to enable you to integrate SAML in seconds 
 * instead of months. We’ve filtered the signal from the noise and come up with a simple setup that will 
 * work for most applications out there.
 * 
 */

defined('MOODLE_INTERNAL') || die;

if ($ADMIN->fulltree) {
    /* Description */
    $settings->add(
        new admin_setting_heading(
            'auth_onelogin_saml/plugindescription',
            '',
            new lang_string('auth_onelogin_samldescription', 'auth_onelogin_saml', $CFG->wwwroot)
        )
    );

    /* IDP */
    $settings->add(
        new admin_setting_heading(
            'auth_onelogin_saml/pluginname',
            new lang_string('auth_onelogin_saml_idp_settings', 'auth_onelogin_saml'),
            new lang_string('auth_onelogin_saml_idp_head', 'auth_onelogin_saml', $CFG->wwwroot)
        )
    );

    $name = 'auth_onelogin_saml/idp_sso_issuer_url';
    $title = get_string('auth_onelogin_saml_idp_sso_issuer_url', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_idp_sso_issuer_url_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_URL);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/idp_sso_target_url';
    $title = get_string('auth_onelogin_saml_idp_sso_target_url', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_idp_sso_target_url_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_URL);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/idp_slo_target_url';
    $title = get_string('auth_onelogin_saml_idp_slo_target_url', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_idp_slo_target_url_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_URL);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/x509certificate';
    $title = get_string('auth_onelogin_saml_x509certificate', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_x509certificate_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtextarea($name, $title, $description, $default, PARAM_RAW);
    $settings->add($setting);

    /* Options */
    $settings->add(
        new admin_setting_heading(
            'auth_onelogin_saml/options',
            new lang_string('auth_onelogin_saml_options', 'auth_onelogin_saml'),
            new lang_string('auth_onelogin_saml_options_head', 'auth_onelogin_saml')
        )
    );
            
    $name = 'auth_onelogin_saml/saml_auto_create_users';
    $title = get_string('auth_onelogin_saml_auto_create_users', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_auto_create_users_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_auto_update_users';
    $title = get_string('auth_onelogin_saml_auto_update_users', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_auto_update_users_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_slo';
    $title = get_string('auth_onelogin_saml_slo', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_slo_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_account_matcher';
    $title = get_string('auth_onelogin_saml_account_matcher', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_account_matcher_description', 'auth_onelogin_saml');
    $default = 'username';
    $choices = array('username' => 'Username', 'email' => 'Email');
    $setting = new admin_setting_configselect($name, $title, $description, $default, $choices);
    $settings->add($setting);

    /* Attribute Mapping */

    // Display locking / mapping of profile fields.
    $authplugin = get_auth_plugin('onelogin_saml');
    $help = get_string('auth_onelogin_saml_attrmapping_head', 'auth_onelogin_saml');
    $help .= get_string('auth_updatelocal_expl', 'auth');
    $help .= get_string('auth_fieldlock_expl', 'auth');
    $custom_user_profile_fields = $authplugin->get_custom_user_profile_fields();
    display_auth_lock_options($settings, $authplugin->authtype, $authplugin->userfields, $help, true, false, $custom_user_profile_fields);
     
    //add username mapping separately (doesn't appear in $authplugin->userfiedls)
    $name = 'auth_onelogin_saml/field_map_username';
    $title = get_string('auth_onelogin_saml_username_map', 'auth_onelogin_saml');
    $description = '';
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_RAW);
    $settings->add($setting);

    //add role mapping
    $name = 'auth_onelogin_saml/field_map_role';
    $title = get_string('auth_onelogin_saml_role_map', 'auth_onelogin_saml');
    $description = '';
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_ALPHANUMEXT);
    $settings->add($setting);

    /* Role Mapping */
    $settings->add(
        new admin_setting_heading(
            'auth_onelogin_saml/rolemapping',
            new lang_string('auth_onelogin_saml_rolemapping', 'auth_onelogin_saml'),
            new lang_string('auth_onelogin_saml_rolemapping_head', 'auth_onelogin_saml')
        )
    );

    $name = 'auth_onelogin_saml/saml_role_siteadmin_map';
    $title = get_string('auth_onelogin_saml_role_siteadmin_map', 'auth_onelogin_saml');
    $description = '';
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_ALPHANUMEXT);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_role_coursecreator_map';
    $title = get_string('auth_onelogin_saml_role_coursecreator_map', 'auth_onelogin_saml');
    $description = '';
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_ALPHANUMEXT);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_role_manager_map';
    $title = get_string('auth_onelogin_saml_role_manager_map', 'auth_onelogin_saml');
    $description = '';
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_ALPHANUMEXT);
    $settings->add($setting);

    /* Advanced Settings */
    $settings->add(
        new admin_setting_heading(
            'auth_onelogin_saml/advancedsettings',
            new lang_string('auth_onelogin_saml_advanced', 'auth_onelogin_saml'),
            new lang_string('auth_onelogin_saml_advanced_head', 'auth_onelogin_saml')
        )
    );

    $name = 'auth_onelogin_saml/saml_debug_mode';
    $title = get_string('auth_onelogin_saml_debug_mode', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_debug_mode_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_strict_mode';
    $title = get_string('auth_onelogin_saml_strict_mode', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_strict_mode_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/sp_entity_id';
    $title = get_string('auth_onelogin_saml_sp_entity_id', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_sp_entity_id_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_RAW);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_nameid_format';
    $title = get_string('auth_onelogin_saml_nameid_format', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_nameid_format_description', 'auth_onelogin_saml');
    $default = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
    $posible_nameidformat_values = array(
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:entity' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName'
    );
    $setting = new admin_setting_configselect($name, $title, $description, $default, $posible_nameidformat_values);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_nameid_encrypted';
    $title = get_string('auth_onelogin_saml_nameid_encrypted', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_nameid_encrypted_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_authn_request_signed';
    $title = get_string('auth_onelogin_saml_authn_request_signed', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_authn_request_signed_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_logout_request_signed';
    $title = get_string('auth_onelogin_saml_logout_request_signed', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_logout_request_signed_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_logout_response_signed';
    $title = get_string('auth_onelogin_saml_logout_response_signed', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_logout_response_signed_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_want_message_signed';
    $title = get_string('auth_onelogin_saml_want_message_signed', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_want_message_signed_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_want_assertion_signed';
    $title = get_string('auth_onelogin_saml_want_assertion_signed', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_want_assertion_signed_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_want_assertion_encrypted';
    $title = get_string('auth_onelogin_saml_want_assertion_encrypted', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_want_assertion_encrypted_description', 'auth_onelogin_saml');
    $default = false;
    $setting = new admin_setting_configcheckbox($name, $title, $description, $default, true, false);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/sp_x509cert';
    $title = get_string('auth_onelogin_saml_sp_x509cert', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_sp_x509cert_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtextarea($name, $title, $description, $default, PARAM_RAW);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/sp_privatekey';
    $title = get_string('auth_onelogin_saml_sp_privatekey', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_sp_privatekey_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtextarea($name, $title, $description, $default, PARAM_RAW);
    $settings->add($setting);

    $name = 'auth_onelogin_saml/saml_logout_redirect_url';
    $title = get_string('auth_onelogin_saml_logout_redirect_url', 'auth_onelogin_saml');
    $description = get_string('auth_onelogin_saml_logout_redirect_url_description', 'auth_onelogin_saml');
    $default = '';
    $setting = new admin_setting_configtext($name, $title, $description, $default, PARAM_URL);
    $settings->add($setting);
}
