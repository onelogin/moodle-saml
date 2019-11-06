<?php 
/* * * * * * * * * *  The OneLogin SAML authentication module for Moodle  * * * * * * * * *
 * 
 * version.php - Code fragment to define the version of onelogin_saml
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

$plugin->component = 'auth_onelogin_saml';
$plugin->version   = 2019110601;  // The current module version (Date: YYYYMMDDXX)
$plugin->requires  = 2017110800;
$plugin->cron      = 0;           // Period for cron to check this module (secs)
$plugin->maturity  = MATURITY_STABLE;
