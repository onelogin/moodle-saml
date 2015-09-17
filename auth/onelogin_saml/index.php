<?php 
/* * * * * * * * * *  The OneLogin SAML 2.0 authentication module for Moodle  * * * * * * * * *
 * 
 * index.php - landing page for auth/onelogin_saml
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

	global $CFG, $USER, $SESSION, $POST, $_POST, $_GET, $_SERVER, $DB, $SITE;

	define('AUTH_ONELOGIN_SAML_RETRIES', 10);

	// do the normal Moodle bootstraping so we have access to all config and the DB
	require_once('../../config.php');

	require_once('functions.php');


	// Normal form failed
	if (isset($_GET['errorcode']) && $_GET['errorcode'] != 4) {
		$location = $CFG->wwwroot.'/login/index.php?normal&errorcode='.$_GET['errorcode'];
		header('Location: '.$location);
		exit();
	}


	/**
	 * check that the saml session is OK - if not, send to OneLogin for authentication
	 * if good, then do the Moodle login, and send to the home page, or landing page
	 * if otherwise specified
	 */

	$retry = isset($SESSION->saml_retry_count) ? $SESSION->saml_retry_count : 0;
	if ($retry == AUTH_ONELOGIN_SAML_RETRIES) {
		// too many tries at logging in
		session_write_close();
		print_error('retriesexceeded', 'auth_onelogin_saml', '', $retry);
	}
	$SESSION->saml_retry_count = $retry + 1;

	// save the jump target - this is checked later that it starts with $CFG->wwwroot, and cleaned
	if (isset($_GET['wantsurl'])) {
		$wantsurl = $SESSION->wantsurl = $_GET['wantsurl'];
	}

	// check for a wantsurl in the existing Moodle session 
	if (empty($wantsurl) && isset($SESSION->wantsurl)) {
		$wantsurl = $SESSION->wantsurl;
	}

	// get the plugin config for saml
	$pluginconfig = get_config('auth/onelogin_saml');
	require_once '_toolkit_loader.php';
	$settings = auth_onelogin_saml_get_settings();
	$auth = new Onelogin_Saml2_Auth($settings);

	if (isset($_GET['logout']) && $_GET['logout']) {
		if (isset($_GET['RelayState']) && !empty($_GET['RelayState'])) {
			$location = $_GET['RelayState'];
		}
		else if (isset($wantsurl)) {
			$location = $wantsurl;
		}
		else {
			$location = $CFG->wwwroot;
		}
	    
		if (isset($_GET['normal'])) {
			auth_onelogin_saml_deleteLocalSession();
		}
		else {
	        if (isset($_GET) && (isset($_GET['SAMLRequest']) || isset($_GET['SAMLResponse']))) {

	            // Delete the local session must be done on processSLO
	            if (isset($_GET['SAMLRequest'])) {
	                auth_onelogin_saml_deleteLocalSession();
	            }	            
	            $auth->processSLO();
	            $errors = $auth->getErrors();
	            if (empty($errors)) {
	                auth_onelogin_saml_deleteLocalSession();
	            }
	            else {
	                print_r(implode(', ', $errors));
	                exit();
	            }
	        }
	        else {
	        	if ($pluginconfig->saml_slo) {
	            	$auth->logout($location);
	            	exit();
	            }
	        }
		}
		if($pluginconfig->saml_logout_redirect_url){
			$location = $pluginconfig->saml_logout_redirect_url;
		}
		header('Location: '.$location);
		exit();
	}


	if (!isset($_POST['SAMLResponse']) && !((isset($_GET['normal']) && $_GET['normal']) || (isset($SESSION->normal) && $SESSION->normal))  && !(isset($_GET['logout']) && $_GET['logout'])) {
		$auth->login();
	} elseif (isset($_POST['SAMLResponse']) && $_POST['SAMLResponse'] && !((isset($_GET['normal']) && $_GET['normal']) || (isset($SESSION->normal) && $SESSION->normal)) && !(isset($_GET['logout']) && $_GET['logout'])) {
		try {
			$auth->processResponse();
			$errors = $auth->getErrors();
			if (empty($errors)) {
				$SESSION->onelogin_saml_nameID = $onelogin_saml_nameId = $auth->getNameId();
				$SESSION->onelogin_saml_login_attributes = $saml_attributes = $auth->getAttributes();
				$wantsurl = isset($SESSION->wantsurl) ? $SESSION->wantsurl : FALSE;
			} else {
				print_error("An invalid SAML response was received from the Identity Provider. Contact the admin.");
				if ($pluginconfig->saml_debug_mode) {
					print_error(implode(', ', $errors));
				}
				exit();
			}
		} catch (Exception $e) {
			print_error("An invalid SAML response was received from the Identity Provider. Contact the admin.");
			if ($pluginconfig->saml_debug_mode) {
				print_error($e->getMessage());
			}
			exit();
		}		
	} else {
		// You shouldn't be able to reach here.
		print_error("Module Setup Error: Review the OneLogin setup instructions for the SAML authentication module, and be sure to change the following one line of code in Moodle's core in 'login/index.php'.<br /><br /><div style=\"text-align:center;\">CHANGE THE FOLLOWING LINE OF CODE (in 'login/index.php')...</div><br /><font style=\"font-size:18px;\"><strong>if (!empty(\$CFG->alternateloginurl)) {</strong></font><br /><br /><div style=\"text-align:center;\">...to...</div><br /><strong><font style=\"font-size:18px;\">if (!empty(\$CFG->alternateloginurl) && !isset(\$_GET['normal'])) { </font></strong> \r\n");
	}

	// Valid session. Register or update user in Moodle, log him on, and redirect to Moodle front
	// we require the plugin to know that we are now doing a saml login in hook puser_login
	$SESSION->onelogin_saml_login = TRUE;

	$samlplugin = get_auth_plugin('onelogin_saml');
	$saml_user = $samlplugin->get_userinfo(null);

	// check user name attribute actually passed
	if($saml_user == false){
		error_log('auth_onelogin_saml: auth failed due to missing username/email saml attribute: '.$pluginconfig->saml_username_map);
		session_write_close();
		$USER = new object();
		$USER->id = 0;
		require_once('../../config.php');
		print_error('auth_onelogin_saml: auth failed due to missing username/email saml attribute: '.$pluginconfig->saml_username_map."<br />".get_string("auth_onelogin_saml_username_email_error", "auth_onelogin_saml")."\r\n");
	}


	if ($_POST['SAMLResponse']) {
		$saml_account_matcher = $pluginconfig->saml_account_matcher;
		if (empty($saml_account_matcher)) {
			$saml_account_matcher = 'username';
		}

		$saml_create = $pluginconfig->saml_auto_create_users == 'on'? true : false;
		$saml_update = $pluginconfig->saml_auto_update_users == 'on'? true : false;
		$USER = auth_onelogin_saml_authenticate_user_login($saml_account_matcher, $saml_user, $saml_create, $saml_update);
	} else {
		print_error("Info received. Finishing authentication process through regular method hook because no SAML response detected.");
		display_object($_POST);
		$USER = authenticate_user_login($saml_user[$saml_account_matcher], time());
	}

	// check that the signin worked
	if ($USER == false) {
		print_error("You could not be identified or created. <br />Login result: FAILURE<br />I have...<br />".htmlspecialchars(print_r($USER, true)));
		session_write_close();
		$USER = new object();
		$USER->id = 0;
		require_once('../../config.php');
		print_error('pluginauthfailed', 'auth_onelogin_saml', '', (!empty($saml_user['username']) ? $saml_user['username'] : $saml_user['email']));
	}

	// complete the user login sequence
	$USER->loggedin = true;
	$USER->site     = $CFG->wwwroot;
	$USER = get_complete_user_data('id', $USER->id);
	complete_user_login($USER);


	// flag this as a SAML based login
	$SESSION->isSAMLSessionControlled = true;
	
	if (isset($wantsurl)) {// and (strpos($wantsurl, $CFG->wwwroot) === 0)
		$urltogo = clean_param($wantsurl, PARAM_URL);
	} else {
		$urltogo = $CFG->wwwroot.'/';
	}
	if (!$urltogo || $urltogo == "") $urltogo = $CFG->wwwroot.'/';

	unset($SESSION->wantsurl);
	redirect($urltogo, 0);
