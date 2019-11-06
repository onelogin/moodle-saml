<?php
/* * * * * * * * * *  The OneLogin SAML authentication module for Moodle  * * * * * * * * *
 *
 * index.php - landing page for auth/onelogin_saml
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

require_once '_toolkit_loader.php';

use OneLogin\Saml2\Auth;


define('AUTH_ONELOGIN_SAML_RETRIES', 100);

// do the normal Moodle bootstraping so we have access to all config and the DB
require_once('../../config.php');

$context = context_system::instance();
$PAGE->set_url('/auth/onelogin_saml/index.php');
$PAGE->set_context($context);

require_once('functions.php');

global $CFG, $USER, $SESSION, $_POST, $_GET, $_SERVER;

// Normal form failed
if (isset($_GET['errorcode']) && $_GET['errorcode'] != 4) {
    $errorCode = clean_param($_GET['errorcode'], PARAM_INT);
    $location = $CFG->wwwroot.'/login/index.php?normal&errorcode='.$errorCode;
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
    exit();
}

$SESSION->saml_retry_count = $retry + 1;

// save the jump target - this is checked later that it starts with $CFG->wwwroot, and cleaned
if (isset($_GET['wantsurl'])) {
    $wantsurl = $SESSION->wantsurl = clean_param($_GET['wantsurl'], PARAM_URL);
}

// check for a wantsurl in the existing Moodle session 
if (empty($wantsurl) && isset($SESSION->wantsurl)) {
    $wantsurl = $SESSION->wantsurl;
}

$normalActived = isset($_GET['normal']);
$normalSessionActivated = isset($SESSION->normal) && $SESSION->normal;
$logoutActived = isset($_GET['logout']) && $_GET['logout'];

// get the plugin config for saml
$pluginconfig = get_config('auth_onelogin_saml');

$settings = auth_onelogin_saml_get_settings();
$auth = new Auth($settings);

if ($logoutActived) {
    if (isset($_GET['RelayState']) && !empty($_GET['RelayState'])) {
        $location = clean_param($_GET['RelayState'], PARAM_URL);
    } else if (isset($wantsurl)) {
        $location = $wantsurl;
    } else {
        $location = $CFG->wwwroot;
    }

    if ($normalActived) {
        auth_onelogin_saml_deleteLocalSession();
    } else {
        if (isset($_GET) && (isset($_GET['SAMLRequest']) || isset($_GET['SAMLResponse']))) {
            // Delete the local session must be done on processSLO
            if (isset($_GET['SAMLRequest'])) {
                auth_onelogin_saml_deleteLocalSession();
            }
            $auth->processSLO();
            $errors = $auth->getErrors();
            if (empty($errors)) {
                auth_onelogin_saml_deleteLocalSession();
            } else {
                print_error('auth_onelogin_saml: '.implode(', ', $errors).'<br><br>'.$auth->getLastErrorReason());
                exit();
            }
        } else if ($pluginconfig->saml_slo) {
            /*

            // Here the session is already closed so can't retrieve
            // the data that was stored.

            $nameid = $sessionIndex = $nameIdFormat = null;

            if (isset($SESSION->onelogin_saml_nameID)) {
                $nameid = $SESSION->onelogin_saml_nameID;
            }
            if (isset($SESSION->onelogin_saml_session_index)) {
                $sessionIndex = $SESSION->onelogin_saml_session_index;
            }
            if (isset($SESSION->onelogin_saml_nameid_format)) {
                $nameIdFormat = $SESSION->onelogin_saml_nameid_format;
            }

			$auth->logout($location, array(), $nameid, $sessionIndex, false, $nameIdFormat);

    		*/
            $auth->logout($location);
            exit();
        }
    }

    if ($pluginconfig->saml_logout_redirect_url) {
        $location = $pluginconfig->saml_logout_redirect_url;
    }

    header('Location: '.$location);
    exit();
} else {
    if (!isset($_POST['SAMLResponse']) && !$normalActived && !$normalSessionActivated && !$logoutActived) {
        $auth->login();
    } else if (isset($_POST['SAMLResponse']) && $_POST['SAMLResponse'] &&
               !$normalActived && !$normalSessionActivated && !$logoutActived) {
        try {
            $auth->processResponse();
            $errors = $auth->getErrors();
            if (empty($errors)) {
                $SESSION->onelogin_saml_nameID = $onelogin_saml_nameId = $auth->getNameId();
                $SESSION->onelogin_saml_login_attributes = $saml_attributes = $auth->getAttributes();
                $wantsurl = isset($SESSION->wantsurl) ? $SESSION->wantsurl : false;

                // Valid session. Register or update user in Moodle, log him on, and redirect to Moodle front
                // we require the plugin to know that we are now doing a saml login in hook puser_login
                $SESSION->onelogin_saml_login = true;
            } else {
                $errorMsg = "auth_onelogin_saml: An invalid SAML response was received from the Identity Provider. Contact the admin.";
                if ($pluginconfig->saml_debug_mode) {
                    $errorMsg .= "<br>".implode(', ', $errors).'<br><br>'.$auth->getLastErrorReason();
                }
            }
        } catch (Exception $e) {
            $errorMsg = "auth_onelogin_saml: An invalid SAML response was received from the Identity Provider. Contact the admin.";
            if ($pluginconfig->saml_debug_mode) {
                $errorMsg .= "<br>".$e->getMessage();
            }
        }
    } else {
        // You shouldn't be able to reach here.
        $errorMsg = "auth_onelogin_saml: Module Setup Error: Review the OneLogin setup instructions for the SAML authentication module";
    }

    if (!isset($errorMsg)) {
        $samlplugin = get_auth_plugin('onelogin_saml');
        $saml_user = $samlplugin->get_userinfo(null);

        // check user name attribute actually passed
        if ($saml_user !== false) {
            if ($_POST['SAMLResponse']) {
                $saml_account_matcher = $pluginconfig->saml_account_matcher;
                if (empty($saml_account_matcher)) {
                    $saml_account_matcher = 'username';
                }

                $saml_create = $pluginconfig->saml_auto_create_users? true : false;
                $saml_update = $pluginconfig->saml_auto_update_users? true : false;
                $USER = auth_onelogin_saml_authenticate_user_login($saml_account_matcher, $saml_user, $saml_create, $saml_update);

                // check that the signin worked
                if ($USER != false) {
                    // complete the user login sequence
                    $USER->loggedin = true;
                    $USER->site = $CFG->wwwroot;
                    $USER = get_complete_user_data('id', $USER->id);
                    complete_user_login($USER);

                    // flag this as a SAML based login
                    $SESSION->isSAMLSessionControlled = true;
                    //$SESSION->onelogin_saml_session_index = $auth->getSessionIndex();
                    //$SESSION->onelogin_saml_nameid_format = $auth->getNameIdFormat();

                    if (isset($wantsurl)) {
                        // and (strpos($wantsurl, $CFG->wwwroot) === 0)
                        $urltogo = clean_param($wantsurl, PARAM_URL);
                    } else {
                        $urltogo = $CFG->wwwroot.'/';
                    }

                    if (!$urltogo || $urltogo == "") {
                        $urltogo = $CFG->wwwroot.'/';
                    }

                    unset($SESSION->wantsurl);
                    redirect($urltogo, 0);
                } else {
                    $errorMsg = "auth_onelogin_saml: You could not be identified or created: ".htmlspecialchars((!empty($saml_user['username']) ? $saml_user['username'] : $saml_user['email']));
                }
            } else {
                $errorMsg = "auth_onelogin_saml: No SAML response detected.";
            }
        } else {
            $errorMsg = 'auth_onelogin_saml: auth failed due to missing username/email saml attribute: '.$pluginconfig->saml_username_map."<br />".get_string("auth_onelogin_saml_username_email_error", "auth_onelogin_saml");
        }

        if (isset($errorMsg)) {
            print_error($errorMsg);
            exit();
        }
    } else {
        print_error($errorMsg);
        exit();
    }
}
