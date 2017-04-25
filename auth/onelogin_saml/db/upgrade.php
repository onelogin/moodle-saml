<?php

defined('MOODLE_INTERNAL') || die();

/**
 * @param int $oldversion the version we are upgrading from
 * @return bool result
 */
function xmldb_auth_onelogin_saml_upgrade($oldversion) {
	if ($oldversion < 2017042501) {
		$pluginconfig = get_config('auth/onelogin_saml');
		if (isset($pluginconfig->saml_username_map) && !empty($pluginconfig->saml_username_map)) {
			set_config('field_map_username', $pluginconfig->saml_username_map, 'auth/onelogin_saml');
		}
		if (isset($pluginconfig->saml_email_map) && !empty($pluginconfig->saml_email_map)) {
			set_config('field_map_email', $pluginconfig->saml_email_map, 'auth/onelogin_saml');
		}
		if (isset($pluginconfig->saml_firstname_map) && !empty($pluginconfig->saml_firstname_map)) {
			set_config('field_map_firstname', $pluginconfig->saml_firstname_map, 'auth/onelogin_saml');
		}
		if (isset($pluginconfig->saml_surname_map) && !empty($pluginconfig->saml_surname_map)) {
			set_config('field_map_lastname', $pluginconfig->saml_surname_map, 'auth/onelogin_saml');
		}
		if (isset($pluginconfig->saml_role_map) && !empty($pluginconfig->saml_role_map)) {
			set_config('field_map_role', $pluginconfig->saml_role_map, 'auth/onelogin_saml');
		}
		if (isset($pluginconfig->saml_idnumber_map) && !empty($pluginconfig->saml_idnumber_map)) {
			set_config('field_map_idnumber', $pluginconfig->saml_idnumber_map, 'auth/onelogin_saml');
		}
	}

	return true;
}