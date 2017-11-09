importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

/*
 * This rule reformats the 204 No Content success response from TOTP validation
 * into something a bit more consistent for the API caller.
 * 
 * Because of where it is used in the manual TOTP authentication policy, it
 * makes the assumption that the TOTP for the username passed as a request
 * parameter has been validated.
 */
var username = context.get(Scope.REQUEST,
		"urn:ibm:security:asf:request:parameter", "username");
success.setValue(false); // this is fine - the backchannel is not trying to
							// establish an authenticated session
page.setValue("/authsvc/authenticator/apimfa/backchannelcomplete.html");
macros.put("@USERNAME@", username);
macros.put("@AUTHNMECHTYPES@", "[\"urn:ibm:security:authentication:asf:mechanism:totp\"]");
