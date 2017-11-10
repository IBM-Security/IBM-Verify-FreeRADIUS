importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

/*
 * This rule is to be used within an InfoMap authentication mechanism to ensure
 * that the calling username is api-client. It is used to ensure certain
 * policies are only invoked via trusted authentication apps.
 */
// This is the old value for behind WebSEAL
var apiuser = context.get(Scope.REQUEST,"urn:ibm:security:asf:request:parameter", "apikey");

IDMappingExtUtils.traceString("apiuser obtained: " + apiuser);

if (apiuser != null && (apiuser.equals("api-client") || apiuser.equals("YXBpLWNsaWVudDpwYXNzdzByZA=="))) {

        var principalID = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter", "username");
        IDMappingExtUtils.traceString("principalID obtained: " + principalID);
        context.set(Scope.SESSION, "urn:ibm:security:asf:request:parameter", "principalID", principalID);

	success.setValue(true);
} else {
	// incorrect API client
	success.setValue(false);
	page.setValue("/authsvc/authenticator/radiustotp/backchannelerror.html");
	macros.put("@ERROR@", "Invalid authentication to this endpoint");	
}
