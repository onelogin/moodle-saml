<?php
/* * * * * * * * * *  The OneLogin SAML authentication module for Moodle  * * * * * * * * *
 * 
 * functions.php - contains the SAML wrapper
 * 
 * @originalauthor OneLogin, Inc
 * @author Harrison Horowitz, Sixto Martin
 * @version 2.0
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package auth/onelogin_saml
 * @requires XMLSecLibs v1.2.2
 * @requires php-saml 
 * @copyright 2011-2014 OneLogin.com
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


	/**
	 * This function returns the SAML settings
	 * 
	 */
	function auth_onelogin_saml_get_settings() {
		
		global $CFG;

		$pluginconfig = get_config('auth/onelogin_saml');

		$settings = array (
			'strict' => ($pluginconfig->saml_strict_mode == 'on')? true: false,
			'debug' =>  ($pluginconfig->saml_debug_mode == 'on')? true: false,
			'idp' => array (
				'entityId' => isset($pluginconfig->idp_sso_issuer_url) ? $pluginconfig->idp_sso_issuer_url : '',
				'singleSignOnService' => array (
					'url' => isset($pluginconfig->idp_sso_target_url) ? $pluginconfig->idp_sso_target_url : '',
				),
				'singleLogoutService' => array (
					'url' => isset($pluginconfig->idp_slo_target_url) ? $pluginconfig->idp_slo_target_url : '',
				),
				'x509cert' => isset($pluginconfig->x509certificate) ? $pluginconfig->x509certificate : '',
			),			
			'sp' => array (
				'entityId' => (!empty($pluginconfig->sp_entity_id)? $pluginconfig->sp_entity_id : 'moodle-php-saml'),
				'assertionConsumerService' => array (
					'url' => htmlspecialchars($CFG->wwwroot.'/auth/onelogin_saml/index.php'),
				),
				'singleLogoutService' => array (
					'url' => htmlspecialchars($CFG->wwwroot.'/auth/onelogin_saml/index.php?logout=1'),
				),
				'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
				'x509cert' => (!empty($pluginconfig->sp_x509cert))? $pluginconfig->sp_x509cert:'',
				'privateKey' => (!empty($pluginconfig->sp_privatekey))? $pluginconfig->sp_privatekey:'',
			),
			'security' => array (
				'signMetadata' => false,
				'nameIdEncrypted' => $pluginconfig->saml_nameid_encrypted == 'on'? true: false,
				'authnRequestsSigned' => $pluginconfig->saml_authn_request_signed == 'on'? true: false,
				'logoutRequestSigned' => $pluginconfig->saml_logout_request_signed == 'on'? true: false,
				'logoutResponseSigned' => $pluginconfig->saml_logout_response_signed == 'on'? true: false,
				'wantMessagesSigned' => $pluginconfig->saml_want_message_signed == 'on'? true: false,
				'wantAssertionsSigned' => $pluginconfig->saml_want_assertion_signed == 'on'? true: false,
				'wantAssertionsEncrypted' => $pluginconfig->saml_want_assertion_encrypted == 'on'? true: false,
			)
		);

		return $settings;
	}

	/**
	 * Copied from moodlelib:authenticate_user_login()
	 * 
	 * WHY? because I need to hard code the plugins to auth_saml, and this user
	 * may be set to any number of other types of login method
	 * 
	 * First of all - make sure that they aren't nologin - we don't mess with that!
	 * 
	 * 
	 * Given a username and password, this function looks them
	 * up using the currently selected authentication mechanism,
	 * and if the authentication is successful, it returns a
	 * valid $user object from the 'user' table.
	 *
	 * Uses auth_ functions from the currently active auth module
	 *
	 * After authenticate_user_login() returns success, you will need to
	 * log that the user has logged in, and call complete_user_login() to set
	 * the session up.
	 *
	 * @uses $CFG
	 * @param string $saml_account_matcher  Field will be used in order to find the user account. 
	 * @param array $user_saml  User's info (with system magic quotes)
	 * @param boolean $saml_create  Auto-provision user
	 * @param boolean $saml_update  Auto-update user	 
	 * @return user|flase A {@link $USER} object or false if error
	 */
	function auth_onelogin_saml_authenticate_user_login($saml_account_matcher, $user_saml, $saml_create=false, $saml_update=false) {

		global $CFG, $DB;

		// ensure that only saml auth module is chosen
		$authsenabled = get_enabled_auth_plugins();
		$password = time();
		$created = false;

		if ($user = get_complete_user_data($saml_account_matcher, $user_saml[$saml_account_matcher])) {
			$auth = empty($user->auth) ? 'manual' : $user->auth;  // use manual if auth not set
			if ($auth=='nologin' or !is_enabled_auth($auth)) {
				add_to_log(0, 'login', 'error', 'index.php', $user_saml[$saml_account_matcher]);
				print_error('[client '.getremoteaddr().'] '.$CFG->wwwroot.'  ---&gt;  DISABLED LOGIN: '.$user_saml[$saml_account_matcher].' '.$_SERVER['HTTP_USER_AGENT']);
				return false;
			}
		} else {
			// check if there's a deleted record (cheaply)
			$query_conditions[$saml_account_matcher] = $user_saml[$saml_account_matcher];
			$query_conditions['deleted'] = 1;
			if ($DB->get_field('user', 'id', $query_conditions)) {
				print_error('[client '.$_SERVER['REMOTE_ADDR'].'] '.  $CFG->wwwroot.'  ---&gt;  DELETED LOGIN: '.$user_saml[$saml_account_matcher].' '.$_SERVER['HTTP_USER_AGENT']);
				return false;
			}

			$auths = $authsenabled;
			$user = new object();
			$user->id = 0;     // User does not exist
		}

		// hard code SAML
		$auths = array('onelogin_saml');
		foreach ($auths as $auth) {
			$authplugin = get_auth_plugin($auth);

			// on auth fail fall through to the next plugin
			if (!$authplugin->user_login($user_saml[$saml_account_matcher], $password)) {
				continue;
			}

			if (!$user->id) {
				// if user not found, 

				// create him
				if ($saml_create) {
					$user = create_user_record($user_saml[$saml_account_matcher], $password, $auth);
					$authplugin->sync_roles($user);
					$created = true;
				}
			}

			if ($user->id && !$created) {
				if (empty($user->auth)) {             // For some reason auth isn't set yet
					$query_conditions['id'] = $user->id;
					$DB->set_field('user', 'auth', $auth, $query_conditions);
					$user->auth = $auth;
				}
				// User already exists in database
				if ($saml_update) {
					if (empty($user->firstaccess)) { //prevent firstaccess from remaining 0 for manual account that never required confirmation
						$query_conditions['id'] = $user->id;
						$DB->set_field('user', 'firstaccess', $user->timemodified, $query_conditions);
						$user->firstaccess = $user->timemodified;
					}
					if (!empty($user_saml['username']) && $user->username != $user_saml['username']) {
						$query_conditions['id'] = $user->id;
						$DB->set_field('user', 'username', $user_saml['username'], $query_conditions);
						$user->email = $user_saml['username'];
					}					
					if (!empty($user_saml['email'])  && $user->email != $user_saml['email']) {
						$query_conditions['id'] = $user->id;
						$DB->set_field('user', 'email', $user_saml['email'], $query_conditions);
						$user->email = $user_saml['email'];
					}
					if (!empty($user_saml['firstname']) && $user->firstname != $user_saml['firstname']) {
						$query_conditions['id'] = $user->id;
						$DB->set_field('user', 'firstname', $user_saml['firstname'], $query_conditions);
						$user->firstname = $user_saml['firstname'];
					}
					if (!empty($user_saml['lastname']) && $user->lastname != $user_saml['lastname']) {
						$query_conditions['id'] = $user->id;
						$DB->set_field('user', 'lastname', $user_saml['lastname'], $query_conditions);
						$user->lastname = $user_saml['lastname'];
					}

					$authplugin->sync_roles($user);
				}

				// we don't want to upset the existing authentication schema for the user
				// update_internal_user_password($user, $password); // just in case salt or encoding were changed (magic quotes too one day)

				// update user record from external DB
				/*
					if (!$authplugin->is_internal()) { 
						$user = update_user_record($user->username, get_auth_plugin($user->auth));
					}
				*/
			}

			foreach ($authsenabled as $hau) {
				$hauth = get_auth_plugin($hau);
				$hauth->user_authenticated_hook($user, $user_saml[$saml_account_matcher], $password);
			}
			if (!$user->id && !$saml_create) {
				print_error("User provided by the IdP". ' "'. $user_saml[$saml_account_matcher] . '" '. "not exists in moodle and auto-provisioning is disabled");
				return false;
			}
			return $user;
		}

		// failed if all the plugins have failed
		add_to_log(0, 'login', 'error', 'index.php', $username);
		print_error('[client '.getremoteaddr()."]  $CFG->wwwroot  ---&gt;  FAILED LOGIN: $username  ".$_SERVER['HTTP_USER_AGENT']);
		return false;
	}

	/**
	 * Add slashes for single quotes and backslashes
	 * so they can be included in single quoted string
	 * (for config.php)
	 */
	function auth_onelogin_saml_addsingleslashes($input){
		return preg_replace("/(['\\\])/", "\\\\$1", $input);
	}

	/**
	 * Like {@link me()} but returns a full URL
	 * @see me()
	 * @return string
	 */
	function auth_onelogin_saml_qualified_me() {

		global $CFG;

		if (!empty($CFG->wwwroot)) {
			$url = parse_url($CFG->wwwroot);
		}

		if (!empty($url['host'])) {
			$hostname = $url['host'];
		} else if (!empty($_SERVER['SERVER_NAME'])) {
			$hostname = $_SERVER['SERVER_NAME'];
		} else if (!empty($_ENV['SERVER_NAME'])) {
			$hostname = $_ENV['SERVER_NAME'];
		} else if (!empty($_SERVER['HTTP_HOST'])) {
			$hostname = $_SERVER['HTTP_HOST'];
		} else if (!empty($_ENV['HTTP_HOST'])) {
			$hostname = $_ENV['HTTP_HOST'];
		} else {
			notify('Warning: could not find the name of this server!');
			return false;
		}

		if (!empty($url['port'])) {
			$hostname .= ':'.$url['port'];
		} else if (!empty($_SERVER['SERVER_PORT'])) {
			if ($_SERVER['SERVER_PORT'] != 80 && $_SERVER['SERVER_PORT'] != 443) {
				$hostname .= ':'.$_SERVER['SERVER_PORT'];
			}
		}

		// TODO, this does not work in the situation described in MDL-11061, but
		// I don't know how to fix it. Possibly believe $CFG->wwwroot ahead of what
		// the server reports.
		if (isset($_SERVER['HTTPS'])) {
			$protocol = ($_SERVER['HTTPS'] == 'on') ? 'https://' : 'http://';
		} else if (isset($_SERVER['SERVER_PORT'])) { # Apache2 does not export $_SERVER['HTTPS']
			$protocol = ($_SERVER['SERVER_PORT'] == '443') ? 'https://' : 'http://';
		} else {
			$protocol = 'http://';
		}

		$url_prefix = $protocol.$hostname;
		return $url_prefix;
	}
	/**
	 * Returns the name of the current script, WITH the querystring portion.
	 * this function is necessary because PHP_SELF and REQUEST_URI and SCRIPT_NAME
	 * return different things depending on a lot of things like your OS, Web
	 * server, and the way PHP is compiled (ie. as a CGI, module, ISAPI, etc.)
	 * <b>NOTE:</b> This function returns false if the global variables needed are not set.
	 *
	 * @return string
	 */
	function auth_onelogin_saml_me() {

		if (!empty($_SERVER['REQUEST_URI'])) {
			return $_SERVER['REQUEST_URI'];

		} else if (!empty($_SERVER['PHP_SELF'])) {
			if (!empty($_SERVER['QUERY_STRING'])) {
				return $_SERVER['PHP_SELF'] .'?'. $_SERVER['QUERY_STRING'];
			}
			return $_SERVER['PHP_SELF'];

		} else if (!empty($_SERVER['SCRIPT_NAME'])) {
			if (!empty($_SERVER['QUERY_STRING'])) {
				return $_SERVER['SCRIPT_NAME'] .'?'. $_SERVER['QUERY_STRING'];
			}
			return $_SERVER['SCRIPT_NAME'];

		} else if (!empty($_SERVER['URL'])) {     // May help IIS (not well tested)
			if (!empty($_SERVER['QUERY_STRING'])) {
				return $_SERVER['URL'] .'?'. $_SERVER['QUERY_STRING'];
			}
			return $_SERVER['URL'];

		} else {
			notify('Warning: Could not find any of these web server variables: $REQUEST_URI, $PHP_SELF, $SCRIPT_NAME or $URL');
			return false;
		}
	}

	function auth_onelogin_saml_err($msg) {
		$stderr = fopen('php://stderr', 'w');
		fwrite($stderr,"auth_plugin_onelogin_saml: ". $msg . "\n");
		fclose($stderr);
	}
	
	function auth_onelogin_saml_deleteLocalSession() {
		if (isset($_SESSION)) {
			foreach($_SESSION as $key => $val) {
				$_SESSION[$key] = ''; // cannot just overwrite session data, causes segfaults in some versions of PHP 
			}
		}
		if(isset($_COOKIE[session_name()])) {
			setcookie(session_name(), '', time()-42000, '/');
		}
		session_destroy();
		ob_clean();
	}

