<?php

/* * * * * * * * * *  The OneLogin SAML Authentication module for Moodle  * * * * * * * * *
 * 
 * auth.php - extends the Moodle core to embrace SAML
 * 
 * @originalauthor OneLogin, Inc
 * @author Harrison Horowitz, Sixto Martin
 * @version 2.3.0
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package auth/onelogin_saml
 * @requires XMLSecLibs v2.0.0-mod
 * @requires php-saml v2.10.0
 * @copyright 2011-2016 OneLogin.com
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
	global $CFG;

	if (strstr(strtolower(PHP_OS), 'win') && strstr(strtolower(PHP_OS), 'darwin') === false) {
		require_once($CFG->libdir.'\authlib.php');
	} else {
		require_once($CFG->libdir.'/authlib.php');
	}

	//if (!defined('MOODLE_INTERNAL')) {
	//	die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
	//}

	/**
	 * OneLogin SAML for Moodle - base definition
	**/
	class auth_plugin_onelogin_saml extends auth_plugin_base {

		/**
		* Constructor.
		*/
		function auth_plugin_onelogin_saml() {
			$this->authtype = 'onelogin_saml';
			$this->roleauth = 'auth_onelogin_saml';
			$this->config = get_config('auth/onelogin_saml');
		}

		/**
		* Returns true if the username and password work and false if they are
		* wrong or don't exist.
		*
		* @param string $username The username (with system magic quotes)
		* @param string $password The password (with system magic quotes)
		* @return bool Authentication success or failure.
		*/
		function user_login($username, $password) {
			global $SESSION;
			// if true, user_login was initiated by onelogin_saml/index.php
			if (isset($SESSION->onelogin_saml_login_attributes)) {
				return TRUE;
			}
			return FALSE;
		}

		/**
		* Returns the user information for 'external' users. In this case the
		* attributes provided by Identity Provider
		*
		* @return array $result Associative array of user data
		*/
		function get_userinfo($username=null) {
			global $SESSION;

			$saml_attributes = $SESSION->onelogin_saml_login_attributes;
			$nameID = $SESSION->onelogin_saml_nameID;
			$mapping = $this->get_attributes();

			if (empty($saml_attributes)) {
				$username = $nameID;
				$email = $username;
			} else {
				$usernameMapping = $mapping['username'];
				$mailMapping =  $mapping['email'];

				if (!empty($usernameMapping) && isset($saml_attributes[$usernameMapping]) && !empty($saml_attributes[$usernameMapping][0])){
					$username = $saml_attributes[$usernameMapping][0];
				}
				if (!empty($mailMapping) && isset($saml_attributes[$mailMapping]) && !empty($saml_attributes[$mailMapping][0])){
					$email = $saml_attributes[$mailMapping][0];
				}
			}

			$user = array();

			if (!empty($username)) {
				$user['username'] = $username;
			}
			if (!empty($email)) {
				$user['email'] = $email;
			}

			$firstnameMapping = $mapping['firstname'];
			$surnameMapping =  $mapping['lastname'];
			$idnumberMapping = $mapping['idnumber'];
			if (!empty($firstnameMapping) && isset($saml_attributes[$firstnameMapping]) && !empty($saml_attributes[$firstnameMapping][0])){
				$user['firstname'] = $saml_attributes[$firstnameMapping][0];
			}
			if (!empty($surnameMapping) && isset($saml_attributes[$surnameMapping]) && !empty($saml_attributes[$surnameMapping][0])){
				$user['lastname'] = $saml_attributes[$surnameMapping][0];
			}
			if (!empty($idnumberMapping) && isset($saml_attributes[$idnumberMapping]) && !empty($saml_attributes[$idnumberMapping][0])){
				$user['idnumber'] = $saml_attributes[$idnumberMapping][0];
			}

			$saml_account_matcher = $this->config->saml_account_matcher;
			if (empty($saml_account_matcher)) {
				$saml_account_matcher = 'username';
			}

			if (($saml_account_matcher == 'username' && empty($user['username']) ||
			  ($saml_account_matcher == 'email' && empty($user['email'])))) {
				$user = False;
			}

			return $user;
		}
		
		/*
		* Returns array containg attribute mappings between Moodle and Identity Provider.
		*/
		function get_attributes() {

			$moodleattributes = array (
				"username" => $this->config->saml_username_map,
				"email" => $this->config->saml_email_map,
				"firstname" => $this->config->saml_firstname_map,
				"lastname" => $this->config->saml_surname_map,
				"idnumber" => $this->config->saml_idnumber_map,
			);

			return $moodleattributes;
		}

		/**
		 * Get and map roles from the saml assertion
		 */
		function obtain_roles() {
			global $SESSION;

			$roles = array();

			$saml_attributes = $SESSION->onelogin_saml_login_attributes;
			$roleMapping = $this->config->saml_role_map;
			if (!empty($roleMapping) && isset($saml_attributes[$roleMapping]) && !empty($saml_attributes[$roleMapping])){
				$siteadminMapping = explode(',', $this->config->saml_role_siteadmin_map);
				$coursecreatorMapping = explode(',', $this->config->saml_role_coursecreator_map);
				$managerMapping = explode(',', $this->config->saml_role_manager_map);

				$samlRoles = $saml_attributes[$roleMapping];

				foreach($samlRoles as $samlRole) {
					if (in_array($samlRole, $siteadminMapping)) {
						$roles[] = 'siteadmin';
					}
					if (in_array($samlRole, $coursecreatorMapping)) {
						$roles[] = 'coursecreator';
					}
					if (in_array($samlRole, $managerMapping)) {
						$roles[] = 'manager';
					}
				}
			}
			return array_unique($roles);
		}

		/**
		* Sync roles for this user - usually creator
		*
		* @param $user object user object (without system magic quotes)
		*/
		function sync_roles($user) {
			global $CFG, $DB;

			$newRoles = $this->obtain_roles();

			// Process siteadmin (special, they are stored at mdl_config)
			if (in_array('siteadmin', $newRoles)) {
				$siteadmins = explode(',', $CFG->siteadmins);
				if (!in_array($user->id, $siteadmins)) {
					$siteadmins[] = $user->id;
					$newAdmins = implode(',', $siteadmins);
					set_config('siteadmins', $newAdmins);
				}
			}

			// Process coursecreator and manager
			$syscontext = context_system::instance();
			if (in_array('coursecreator', $newRoles)) {
				$creatorrole = $DB->get_record('role', array('shortname'=>'coursecreator'), '*', MUST_EXIST);
				role_assign($creatorrole->id, $user->id, $syscontext);
				}
			if (in_array('manager', $newRoles)) {
				$managerrole = $DB->get_record('role', array('shortname'=>'manager'), '*', MUST_EXIST);
				role_assign($managerrole->id, $user->id, $syscontext);
			}
		}

		/**
		* Returns true if this authentication plugin is 'internal'.
		*
		* @return bool
		*/
		function is_internal() {
			return false;
		}


		function prevent_local_passwords() {
		    return true;
		}

		/**
		* Returns true if this authentication plugin can change the user's
		* password.
		*
		* @return bool
		*/
		function can_change_password() {
			return false;
		}

		function loginpage_hook() {
			global $CFG;
			// Prevent username from being shown on login page after logout
			$CFG->nolastloggedin = true;

			if (!isset($_GET['normal']) && (empty($_POST['username']) && empty($_POST['password']))) {
				$init_sso_url = $CFG->wwwroot.'/auth/onelogin_saml/index.php';
				redirect($init_sso_url);
			}
		}

		function logoutpage_hook() {
			global $SESSION, $CFG;
			
			$logout_url = $CFG->wwwroot.'/auth/onelogin_saml/index.php?logout=1';

			if (!isset($SESSION->isSAMLSessionControlled)) {
				$logout_url .= '&normal';
			}

			require_logout();
			set_moodle_cookie('nobody');
			redirect($logout_url);
		}
		
		/**
		* Prints a form for configuring this authentication plugin.
		*
		* This function is called from admin/auth.php, and outputs a full page with
		* a form for configuring this plugin.
		*
		* @param array $page An object containing all the data for this page.
		*/

		function config_form($config, $err, $user_fields) {
			include "config.html";
		}

		/**
		 * A chance to validate form data, and last chance to
		 * do stuff before it is inserted in config_plugin
		 */
		function validate_form($form, &$err) {
			if (empty($form->idp_sso_issuer_url)) {
				$err['idp_sso_issuer_url_empty'] = '"'.get_string('auth_onelogin_saml_idp_sso_issuer_url', 'auth_onelogin_saml').'" '. get_string('auth_onelogin_saml_empty_required_value', 'auth_onelogin_saml');
			}
			if (empty($form->idp_sso_target_url)) {
				$err['idp_sso_target_url_empty'] = '"'.get_string('auth_onelogin_saml_idp_sso_target_url', 'auth_onelogin_saml').'" '. get_string('auth_onelogin_saml_empty_required_value', 'auth_onelogin_saml');
			}

			if (!empty($form->saml_auto_create_users) || !empty($form->saml_auto_update_users)) {

				if (empty($form->saml_username_map)) {
					$err['saml_username_map_empty'] = get_string('auth_onelogin_saml_create_or_update_warning', 'auth_onelogin_saml').' "'.get_string('auth_onelogin_saml_username_map', 'auth_onelogin_saml').'" '. get_string('auth_onelogin_saml_empty_required_value', 'auth_onelogin_saml');
				}
				if (empty($form->saml_email_map)) {
					$err['saml_email_map_empty'] = get_string('auth_onelogin_saml_create_or_update_warning', 'auth_onelogin_saml').' "'.get_string('auth_onelogin_saml_email_map', 'auth_onelogin_saml').'" '. get_string('auth_onelogin_saml_empty_required_value', 'auth_onelogin_saml');
				}
				if (empty($form->saml_firstname_map)) {
					$err['saml_firstname_map_empty'] = get_string('auth_onelogin_saml_create_or_update_warning', 'auth_onelogin_saml').' "'.get_string('auth_onelogin_saml_firstname_map', 'auth_onelogin_saml').'" '. get_string('auth_onelogin_saml_empty_required_value', 'auth_onelogin_saml');
				}
				if (empty($form->saml_surname_map)) {
					$err['saml_surname_map_empty'] = get_string('auth_onelogin_saml_create_or_update_warning', 'auth_onelogin_saml').' "'.get_string('auth_onelogin_saml_surname_map', 'auth_onelogin_saml').'" '. get_string('auth_onelogin_saml_empty_required_value', 'auth_onelogin_saml');
				}
			}
		}

		/**
		* Processes and stores configuration data for this authentication plugin.
		*
		*
		* @param object $config Configuration object
		*/
		function process_config($config) {


			if (!isset($config->idp_sso_target_url)) {
				$config->idp_sso_target_url = '';
			}
			if (!isset($config->idp_sso_issuer_url)) {
				$config->idp_sso_issuer_url = '';
			}
			if (!isset($config->idp_slo_target_url)) {
				$config->idp_slo_target_url = '';
			}
			if (!isset($config->x509certificate)) {
				$config->x509certificate = '';
			}

			if (!isset($config->saml_auto_create_users)) {
				$config->saml_auto_create_users = '';
			}
			if (!isset($config->saml_auto_update_users)) {
				$config->saml_auto_update_users = '';
			}
			if (!isset($config->saml_slo)) {
				$config->saml_slo = '';
			}
			if (!isset($config->saml_account_matcher)) {
				$config->saml_account_matcher = '';
			}

			if (!isset($config->saml_username_map)) {
				$config->saml_username_map = '';
			}
			if (!isset($config->saml_email_map)) {
				$config->saml_email_map = '';
			}    
			if (!isset($config->saml_firstname_map)) {
				$config->saml_firstname_map = '';
			}
			if (!isset($config->saml_surname_map)) {
				$config->saml_surname_map = '';
			}
			if (!isset($config->saml_idnumber_map)) {
				$config->saml_idnumber_map = '';
			}
			if (!isset($config->saml_role_map)) {
				$config->saml_role_map = '';
			}

			if (!isset($config->saml_role_siteadmin_map)) {
				$config->saml_role_siteadmin_map = '';
			}
			if (!isset($config->saml_role_coursecreator_map)) {
				$config->saml_role_coursecreator_map = '';
			}
			if (!isset($config->saml_role_manager_map)) {
				$config->saml_role_manager_map = '';
			}

			if (!isset($config->saml_debug_mode)) {
				$config->saml_debug_mode = '';
			}
			if (!isset($config->saml_strict_mode)) {
				$config->saml_strict_mode = '';
			}
			if (!isset($config->sp_entity_id)) {
				$config->sp_entity_id = '';
			}
			if (!isset($config->saml_nameid_encrypted)) {
				$config->saml_nameid_encrypted = '';
			}
			if (!isset($config->saml_authn_request_signed)) {
				$config->saml_authn_request_signed = '';
			}
			if (!isset($config->saml_logout_request_signed)) {
				$config->saml_logout_request_signed = '';
			}
			if (!isset($config->saml_logout_response_signed)) {
				$config->saml_logout_response_signed = '';
			}
			if (!isset($config->saml_want_message_signed)) {
				$config->saml_want_message_signed = '';
			}
			if (!isset($config->saml_want_assertion_signed)) {
				$config->saml_want_assertion_signed = '';
			}
			if (!isset($config->saml_want_assertion_encrypted)) {
				$config->saml_want_assertion_encrypted = '';
			}
			if (!isset($config->sp_x509cert)) {
				$config->sp_x509cert = '';
			}
			if (!isset($config->sp_privatekey)) {
				$config->sp_privatekey = '';
			}
			if (!isset($config->saml_logout_redirect_url)) {
				$config->saml_logout_redirect_url = '';
			}
			
			set_config('idp_sso_target_url', trim($config->idp_sso_target_url), 'auth/onelogin_saml');
			set_config('idp_sso_issuer_url', trim($config->idp_sso_issuer_url), 'auth/onelogin_saml');
			set_config('idp_slo_target_url', trim($config->idp_slo_target_url), 'auth/onelogin_saml');
			set_config('x509certificate', trim($config->x509certificate), 'auth/onelogin_saml');			
			set_config('saml_auto_create_users',  $config->saml_auto_create_users, 'auth/onelogin_saml');

			set_config('saml_auto_update_users',  $config->saml_auto_update_users, 'auth/onelogin_saml');
			set_config('saml_slo',  $config->saml_slo, 'auth/onelogin_saml');
			set_config('saml_account_matcher',  $config->saml_account_matcher, 'auth/onelogin_saml');
			set_config('saml_username_map',  trim($config->saml_username_map), 'auth/onelogin_saml');
			set_config('saml_email_map',  trim($config->saml_email_map), 'auth/onelogin_saml');
			set_config('saml_email_map',  trim($config->saml_email_map), 'auth/onelogin_saml');
			set_config('saml_firstname_map',  trim($config->saml_firstname_map), 'auth/onelogin_saml');
			set_config('saml_surname_map',  trim($config->saml_surname_map), 'auth/onelogin_saml');
			set_config('saml_idnumber_map',  trim($config->saml_idnumber_map), 'auth/onelogin_saml');
			set_config('saml_role_map',  trim($config->saml_role_map), 'auth/onelogin_saml');
			set_config('saml_role_siteadmin_map',  trim($config->saml_role_siteadmin_map), 'auth/onelogin_saml');
			set_config('saml_role_coursecreator_map',  trim($config->saml_role_coursecreator_map), 'auth/onelogin_saml');
			set_config('saml_role_manager_map',  trim($config->saml_role_manager_map), 'auth/onelogin_saml');
			set_config('saml_debug_mode',  $config->saml_debug_mode, 'auth/onelogin_saml');
			set_config('saml_strict_mode',  $config->saml_strict_mode, 'auth/onelogin_saml');
			set_config('sp_entity_id',  trim($config->sp_entity_id), 'auth/onelogin_saml');
			set_config('saml_nameid_encrypted',  $config->saml_nameid_encrypted, 'auth/onelogin_saml');
			set_config('saml_authn_request_signed',  $config->saml_authn_request_signed, 'auth/onelogin_saml');
			set_config('saml_logout_request_signed',  $config->saml_logout_request_signed, 'auth/onelogin_saml');
			set_config('saml_logout_response_signed',  $config->saml_logout_response_signed, 'auth/onelogin_saml');
			set_config('saml_want_message_signed',  $config->saml_want_message_signed, 'auth/onelogin_saml');
			set_config('saml_want_assertion_signed',  $config->saml_want_assertion_signed, 'auth/onelogin_saml');
			set_config('saml_want_assertion_encrypted',  $config->saml_want_assertion_encrypted, 'auth/onelogin_saml');
			set_config('sp_x509cert',  trim($config->sp_x509cert), 'auth/onelogin_saml');
			set_config('sp_privatekey',  trim($config->sp_privatekey), 'auth/onelogin_saml');
			set_config('saml_logout_redirect_url',  trim($config->saml_logout_redirect_url), 'auth/onelogin_saml');

			return true;
		}
		

		/**
		* Test if settings are ok, print info to output.
		* 
		*/
		public function test_settings() {
			global $CFG, $OUTPUT;

			$pluginconfig = get_config('auth/onelogin_saml');

			require_once 'functions.php';
			require_once '_toolkit_loader.php';
			$settings = auth_onelogin_saml_get_settings();

			echo $OUTPUT->notification('Debug mode '. ($settings['strict']?'<strong>on</strong>. '."In production turn it off":'<strong>off</strong>'), 'userinfobox notifysuccess');
			echo $OUTPUT->notification('Strict mode '. ($settings['debug']?'<strong>on</strong>':'<strong>off</strong>. '."In production we recommend to turn it on."), 'userinfobox notifysuccess');

			$spPrivatekey = $settings['sp']['x509cert'];
			$spCert = $settings['sp']['privateKey'];

			try {
				$samlSettings = new OneLogin_Saml2_Settings($settings);
				echo $OUTPUT->notification('SAML settings are <strong>ok</strong>', 'userinfobox notifysuccess');
			} catch (Exception $e) {
				echo $OUTPUT->notification('Found errors while validating SAML settings info.<br>'.$e->getMessage(), 'userinfobox notifyproblem');
			}

			if ($pluginconfig->saml_slo == 'on') {
				echo $OUTPUT->notification("Single Log Out is enabled. If the SLO process fail, close your browser to be sure that session of the apps are closed.", 'userinfobox notifysuccess');
			} else {
				echo $OUTPUT->notification("Single Log Out is disabled. If you log out from Wordpress your session at the IdP keeps alive.", 'userinfobox notifysuccess');
			}

			$fileSystemKeyExists = file_exists($CFG->dirroot.'/auth/onelogin_saml/certs/sp.key');
			$fileSystemCertExists = file_exists($CFG->dirroot.'/auth/onelogin_saml/certs/sp.crt');
			if ($fileSystemKeyExists) {
				$privatekey_url = $CFG->wwwroot . '/auth/onelogin_saml/certs/sp.key';
				echo $OUTPUT->notification("There is a private key stored at the filesystem. Protect the 'certs' path. Nobody should be allowed to access:".'<br>'.$privatekey_url.'<br>', 'userinfobox');
			}

			if ($spPrivatekey && !empty($spPrivatekey)) {
				echo $OUTPUT->notification("There is a private key stored at the database. (An attacker could own your database and get it. Take care)", 'userinfobox');
			}

			if (($spPrivatekey && !empty($spPrivatekey) && $fileSystemKeyExists) ||
				($spCert && !empty($spCert) && $fileSystemCertExists)) {
				echo $OUTPUT->notification("Private key/certs stored on database have priority over the private key/cert stored at filesystem", 'userinfobox');
			}

			if ($pluginconfig->saml_auto_create_users) {
				echo $OUTPUT->notification("User will be created if not exists, based on the data sent by the IdP.", 'userinfobox notifysuccess');
			} else {
				echo $OUTPUT->notification("If the user not exists, access is prevented.", 'userinfobox notifysuccess');
			}

			if ($pluginconfig->saml_auto_update_users) {
				echo $OUTPUT->notification("User account will be updated with the data sent by the IdP.", 'userinfobox notifysuccess');
			}

			if ($pluginconfig->saml_auto_create_users || $pluginconfig->saml_auto_update_users) {
				echo $OUTPUT->notification("Is important to set the attribute and the role mapping when auto-provisioning or account update are active.", 'userinfobox');
			}

			$attr_mappings = array (
				'saml_username_map' => get_string("auth_onelogin_saml_username_map", "auth_onelogin_saml"),
				'saml_email_map' => get_string("auth_onelogin_saml_email_map", "auth_onelogin_saml"),
				'saml_firstname_map' => get_string("auth_onelogin_saml_firstname_map", "auth_onelogin_saml"),
				'saml_surname_map' => get_string("auth_onelogin_saml_surname_map", "auth_onelogin_saml"),
				'saml_idnumber_map' => get_string("auth_onelogin_saml_idnumber_map", "auth_onelogin_saml"),
				'saml_role_map' => get_string("auth_onelogin_saml_role_map", "auth_onelogin_saml"),
			);

			$saml_account_matcher = $pluginconfig->saml_account_matcher;
			if (empty($saml_account_matcher)) {
				$saml_account_matcher = 'username';
			}

			$lacked_attr_mappings = array();
			foreach ($attr_mappings as $field => $name) {
				$value = $pluginconfig->{"$field"};
				if (empty($value)) {
					if ($saml_account_matcher == 'username' && $field == 'saml_username_map') {
						echo $OUTPUT->notification("Username mapping is required in order to enable the SAML Single Sign On", 'userinfobox notifyproblem');
					}
					if ($saml_account_matcher == 'email' && $field == 'saml_email_map') {
						echo $OUTPUT->notification("Email Address mapping is required in order to enable the SAML Single Sign On", 'userinfobox notifyproblem');
					}
					$lacked_attr_mappings[] = $name;
				}
			}

			if (!empty($lacked_attr_mappings)) {
				echo $OUTPUT->notification("Notice that there are attributes without mapping:<br>".implode('<br>', $lacked_attr_mappings), 'userinfobox');
			}

			$role_mappings = array (
				'saml_role_siteadmin_map' => get_string("auth_onelogin_saml_rolemapping_head", "auth_onelogin_saml"),
				'saml_role_coursecreator_map' => get_string("auth_onelogin_saml_role_coursecreator_map", "auth_onelogin_saml"),
				'saml_role_manager_map' => get_string("auth_onelogin_saml_role_manager_map", "auth_onelogin_saml"),				
			);

			$lacked_role_mappings = array();
			foreach ($role_mappings as $field => $name) {
				$value = $pluginconfig->{"$field"};
				if (empty($value)) {
					$lacked_role_mappings[] = $name;
				}
			}

			if (!empty($lacked_role_mappings)) {
				echo $OUTPUT->notification("Notice that there are roles without mapping:<br>".implode('<br>', $lacked_role_mappings), 'userinfobox');
			}
		}
	}
