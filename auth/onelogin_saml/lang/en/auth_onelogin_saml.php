<?php
	global $CFG;

	$string['auth_onelogin_samltitle']         = 'OneLogin SAML'; //SSO Authentication
	
	
	
	$string['auth_onelogin_samldescription']   = '
		<p style="text-align:center;" align="center"><strong><span style=" text-decoration:underline;">
			Single Sign-On (SSO) SAML-based authentication by the one and only...</span> <br /><br /><a href="http://www.onelogin.com/" style="text-decoration:none;font-size:24px;"><img alt="OneLogin" src="'.$CFG->wwwroot.'/auth/onelogin_saml/onelogin.png"></a></strong>
		</p>
		<p>
			Security Assertion Markup Language (SAML) is a standard for logging users into applications based 
			on their session in another context. This has significant advantages over logging in using a 
			username/password: no need to type in credentials, no need to remember and renew password, no weak
			passwords etc. Most companies already know the identity of users because they are logged into their Active Directory
			domain or intranet. It is natural to use this information to log users into other applications as well 
			such as web-based application, and one of the more elegant ways of doing this by using SAML. SAML is very powerful and flexible, 
			but the specification can be quite a handful. Now OneLogin is releasing this SAML toolkit for your Moodle application to enable you 
			to integrate SAML in seconds instead of months. We\'ve filtered the signal from the noise and come up with a simple setup that will work for most 
			applications out there.
		</p>
		<br />
		<p style="font-weight:bold; text-decoration:underline; text-align:center;">Module Setup Notes</p>
		<div align="center">
			<p style="text-align:center">
				<div align="center" style="width:700px; text-align:center;">
					<div align="left">
						<p align="left">
							For the greatest convenience and security, be sure to perform the following steps...
							<br />
							<ul>
								<li>
									Go to your <a target="_blank" title="New Window" href="'.$CFG->wwwroot.'/admin/settings.php?section=manageauths">Manage Authentication</a> page and...
									<ul>
										<li>
											Enable the OneLogin SAML authentication module by clicking on the eyeball so that the eye is open.
										</li>
										<li>
											Click the UP arrow to prioritize the SAML authentication above all of the others.
										</li>
										<li>
											Disable "Self-registration" (optional but recommended)
										</li>
										<li>
											In the "Alternative login URL" textbox   <strong>&larr;   '.$CFG->wwwroot.'/auth/onelogin_saml</strong>
										</li>
									</ul>
								</li>
								<li>
									Configure the options below from your company\'s OneLogin Moodle connector.
								</li>
							</ul>
							<br />
						</p>
					</div>
				</div>
			</p>
			<p style="text-align:center; padding-left:175px;">
				<div align="center" style="background-color:#006600; width:620px; padding:1px; text-align:center;">
					<p align="center" style="text-weight:bold; background-color:#FFFFFF; width:98%; padding-top:5px; padding-bottom:5px;">
						<span style="font-weight:bold;"><i>SECRET  FOR  ADMINS</i></span>
						<br /><br /> Skip the SAML process and see the regular login box by adding <span style="font-size:24px;">&ldquo;</span>?normal<span style="font-size:24px;">&rdquo;</span> to your normal login URL.
						<br /> <a href="'.$CFG->wwwroot.'/login/index.php?normal" title="Normal login mode">'.$CFG->wwwroot.'/login/index.php?normal</a>
						<br />
						<br /><strong>To enable this feature, you must find the 1 line of code in "/login/index.php" that looks like...</strong>
						<br /><span style="font-size:24px;">&ldquo;</span>if (!empty($CFG->alternateloginurl)) {<span style="font-size:24px;">&rdquo;</span>
						<br /><strong>...and change it to...</strong>
						<br /><span style="font-size:24px;">&ldquo;</span>if (!empty($CFG->alternateloginurl) && !isset($_GET[\'normal\'])) {<span style="font-size:24px;">&rdquo;</span>
					</p>
				</div>
			</p>
		</div>
	</div>';

	$string['auth_onelogin_saml_idp_head'] = "Set here some info related to the IdP that will be connected with our Wordpress. You can find this values at the Onelogin's platform in the Moodle App at the Single Sign-On tab";
	$string['auth_onelogin_saml_idp_sso_issuer_url'] = 'IdP Entity Id';
	$string['auth_onelogin_saml_idp_sso_issuer_url_description'] = 'Identifier of the IdP entity. ("Issuer URL")';
	$string['auth_onelogin_saml_idp_sso_target_url'] = 'Single Sign On Service Url';
	$string['auth_onelogin_saml_idp_sso_target_url_description'] = 'SSO endpoint info of the IdP. URL target of the IdP where the SP will send the Authentication Request. ("SAML 2.0 Endpoint (HTTP)")';
	$string['auth_onelogin_saml_idp_slo_target_url'] = 'Single Log Oout Service Url';
	$string['auth_onelogin_saml_idp_slo_target_url_description'] = 'SLO endpoint info of the IdP. URL target of the IdP where the SP will send the SLO Request. ("SLO Endpoint (HTTP)")';
	$string['auth_onelogin_saml_x509certificate'] = 'X.509 Certificate';
	$string['auth_onelogin_saml_x509certificate_description'] = 'Public x509 certificate of the IdP. ("X.509 certificate")';


	$string['auth_onelogin_saml_options_head'] = "In this section the behavior of the plugin is set.";
	$string['auth_onelogin_saml_auto_create_users'] = 'Create user if not exists';
	$string['auth_onelogin_saml_auto_create_users_description'] = 'Auto-provisioning. If user not exists, Wordpress will create a new user with the data provided by the IdP. Review the Mapping section.<br />By default, the accounts are created without a password, and the user must login via SAML identity verification.';
	$string['auth_onelogin_saml_auto_update_users'] = 'Update user data';
	$string['auth_onelogin_saml_auto_update_users_description'] = 'Auto-update. Wordpress will update the account of the user with the data provided by the IdP. Review the Mapping section.';
	$string['auth_onelogin_saml_slo'] = 'Single Log Out';
	$string['auth_onelogin_saml_slo_description'] = 'Enable/disable Single Log Out. SLO is a complex functionality, the most common SLO implementation is based on front-channel (redirections), sometimes if the SLO workflow fails a user can be blocked in an unhandled view. If the admin does not controls the set of apps involved in the SLO process maybe is better to disable this functionality due could carry more problems than benefits.';
	$string['auth_onelogin_saml_account_matcher'] = 'Match Moodle account by';
	$string['auth_onelogin_saml_account_matcher_description'] = "Select what field will be used in order to find the user account. We recomment to use the 'username' becouse is an attribute that the user can't change. If you select the 'email' and the user change his value in Moodle, he will lost the access.";

	$string['auth_onelogin_saml_attrmapping_head'] = "Sometimes the names of the attributes sent by the IdP not match the names used by Wordpress for the user accounts. In this section we can set the mapping between IdP fields and Moodle fields.";
	$string['auth_onelogin_saml_username_map'] = "Username";
	$string['auth_onelogin_saml_email_map'] = "Email Address";
	$string['auth_onelogin_saml_firstname_map'] = "First Name";
	$string['auth_onelogin_saml_surname_map'] = "Surname";
	$string['auth_onelogin_saml_role_map'] = "Role";	

	$string['auth_onelogin_saml_rolemapping_head'] = "The IdP can use it's own roles. Set in this section the mapping between IdP and Moodle roles. Accepts multiple valued comma separated. Example: admin,owner,superuser.";
	$string['auth_onelogin_saml_role_siteadmin_map'] = "Site administrators";
	$string['auth_onelogin_saml_role_coursecreator_map'] = "Course creator";
	$string['auth_onelogin_saml_role_manager_map'] = "Manager";

	$string['auth_onelogin_saml_advanced_head'] = "Handle some other parameters related to customizations and security issues.<br>If sign/encryption is enabled, then x509 cert and private key for the SP must be provided. There are 2 ways:<br>1. Store them as files named sp.key and sp.crt on the 'certs' folder of the plugin. (be sure that the folder is protected and not exposed to internet)<br>2. Store them at the database, filling the corresponding textareas. (take care of security issues)";

	$string['auth_onelogin_saml_debug_mode'] = "Debug Mode";
	$string['auth_onelogin_saml_debug_mode_description'] = "Enable it when your are debugging the SAML workflow. Errors and Warnigs will be showed.";
	$string['auth_onelogin_saml_strict_mode'] = "Strict Mode";
	$string['auth_onelogin_saml_strict_mode_description'] = "If Strict mode is Enabled, then Wordpress will reject unsigned or unencrypted messages if it expects them signed or encrypted. Also will reject the messages if not strictly follow the SAML standard: Destination, NameId, Conditions ... are validated too.";
	$string['auth_onelogin_saml_sp_entity_id'] = "Service Provider Entity Id";
	$string['auth_onelogin_saml_sp_entity_id_description'] = "Set the Entity ID for the Service Provider. If not provided, 'moodle-php-saml' will be used.<br>Set this value as a Valid Audience at the Onelogin Platform.";
	$string['auth_onelogin_saml_nameid_encrypted'] = "Encrypt nameID";
	$string['auth_onelogin_saml_nameid_encrypted_description'] = "The nameID sent by this SP will be encrypted.";
	$string['auth_onelogin_saml_authn_request_signed'] = "Sign AuthnRequest";
	$string['auth_onelogin_saml_authn_request_signed_description'] = "The samlp:AuthnRequest messages sent by this SP will be signed.";
	$string['auth_onelogin_saml_logout_request_signed'] = "Sign LogoutRequest";
	$string['auth_onelogin_saml_logout_request_signed_description'] = "The samlp:logoutRequest messages sent by this SP will be signed.";
	$string['auth_onelogin_saml_logout_response_signed'] = "Sign LogoutResponse";
	$string['auth_onelogin_saml_logout_response_signed_description'] = "The samlp:logoutResponse messages sent by this SP will be signed.";
	$string['auth_onelogin_saml_want_message_signed'] = "Reject Unsigned Messages";
	$string['auth_onelogin_saml_want_message_signed_description'] = "Reject unsigned samlp:Response, samlp:LogoutRequest and samlp:LogoutResponse received";
	$string['auth_onelogin_saml_want_assertion_signed'] = "Reject Unsigned Assertions";
	$string['auth_onelogin_saml_want_assertion_signed_description'] = "Reject unsigned saml:Assertion received";
	$string['auth_onelogin_saml_want_assertion_encrypted'] = "Reject Unencrypted Assertions";
	$string['auth_onelogin_saml_want_assertion_encrypted_description'] = "Reject unencrypted saml:Assertion received";							
	$string['auth_onelogin_saml_sp_x509cert'] = "Service Provider X.509 Certificate";
	$string['auth_onelogin_saml_sp_x509cert_description'] = "Public x509 certificate of the SP. Leave this field empty if you gonna provide the private key by the sp.crt";
	$string['auth_onelogin_saml_sp_privatekey'] = "Service Provider Private Key";
	$string['auth_onelogin_saml_sp_privatekey_description'] = "Private Key of the SP. Leave this field empty if you gonna provide the private key by the sp.key";

	$string['auth_onelogin_saml_form_has_errors'] = "The SAML settings form has errors";
	$string['auth_onelogin_saml_create_or_update_warning'] = "When auto-provisioning or auto-update is enable,";
	$string['auth_onelogin_saml_empty_required_value'] = "is a required attribute, provide a valid value";

	$string['auth_onelogin_saml_metadatalink'] = 'Go to the metadata of this SP';
	$string['auth_onelogin_saml_validatelink'] = 'Once configured, validate here your OneLogin SSO/SAML Settings';

	$string['retriesexceeded'] = 'Maximum number of SAML connection retries exceeded  - there must be a problem with the Identity Service.<br />Please try again in a few minutes.';
	$string['pluginauthfailed'] = 'The OneLogin SAML authentication plugin failed - user $a disallowed (no user auto-creation?) or dual login disabled.';
	$string['pluginauthfailedusername'] = 'The OneLogin SAML authentication plugin failed - user $a disallowed due to invalid username format.';
	$string['auth_onelogin_saml_username_email_error'] = 'The identity provider returned a set of data that does not contain the SAML username/email mapping field. Once of this field is required to login. <br />Please check your Username/Email Address Attribute Mapping configuration.';

	$string['pluginname'] = 'OneLogin SAML SSO Authentication';


?>