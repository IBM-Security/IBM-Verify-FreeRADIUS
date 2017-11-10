importPackage(Packages.com.tivoli.am.fim.trustserver.sts.utilities);
importClass(Packages.com.ibm.security.access.user.UserLookupHelper);
importClass(Packages.com.ibm.security.access.user.User);

function setFailed(principalID, errMsg, traceMsg, pageUrl){
	IDMappingExtUtils.traceString(traceMsg);
	context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", principalID);
	success.setValue(false);
	macros.put("@ERROR_MESSAGE@",errMsg);
	if (pageUrl != null){
		page.setValue(pageUrl);
	}
}

var principalID = context.get(Scope.SESSION, "urn:ibm:security:asf:request:parameter", "principalID");

IDMappingExtUtils.traceString("got a principalID: " + principalID);

if(principalID != null && principalID != "") {

	var hlpr = new UserLookupHelper();
	// Init with our authsvc config
	hlpr.init(true);

	var searched = hlpr.search("imsAuthCredValues",principalID,10);

	if(searched.length < 1) {
		setFailed(principalID,"Incorrect username.","No accounts found for user : " + principalID, null);	
	} else if (searched.length > 1) {
		setFailed(principalID,"System Error","Multiple accounts found for user : " + principalID, null);
	}
	if(searched.length == 1) {
		try {
				var user = hlpr.getUserByNativeId(searched[0]);
				if(user.getAttribute("imsOrgIDHRStatus").trim().toLowerCase() != "active" ){
					setFailed(user.getId(),"User is not active.","User account is not active : " + principalID, null);
				}
			} catch (ex) {
				setFailed(user.getId(),"System Error","Incorrect configured account : " + principalID, null);
			}
	}

	if(user != null) {
		IDMappingExtUtils.traceString("found user: " + user.getAttribute("imsAuthCredValueDefault"));
                context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "username", user.getAttribute("imsAuthCredValueDefault").toLowerCase()); 
                success.setValue(true);
	} else { 
		setFailed(principalID,"Incorrect username ","User not found : " + principalID, null);
	}
}
