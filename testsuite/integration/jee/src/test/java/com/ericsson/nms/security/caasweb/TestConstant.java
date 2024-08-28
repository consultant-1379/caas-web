/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.nms.security.caasweb;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author edobpet
 */
public enum TestConstant {

    AUTHENTICATION("1.3.6.1.4.1.193.140.1.1"),
    AUTHORIZATION("1.3.6.1.4.1.193.140.1.2"),
    certFolder("src/main/resources/"),
    PROTOCOL_VERSION("0"),
    PROFILE_SEPARATOR(";"),
    caas_web_client_keystore(certFolder + "caas-web-client-keystore.jks"),
    caas_web_client_trustore(certFolder + "caas-web-client-trustore"),
    caas_web_server_keystore(certFolder + "caas-web-server-keystore.jks"),
    caas_web_server_trustore(certFolder + "caas-web-server-trustore"),
    PASSWORD("changeit"),
    resourcePackages("com.ericsson.nms.security.caasweb;com.ericsson.oss.itpf.rest"),
    queryTypeKey("queryType"),
    aaqVersionKey("aaqVersion"),
    userIDkey("userID"),
    //to be remove when IDM is deliverd
    userIDvalue("testuser"),
    sessionIDkey("sessionID"),
    sessionIDvalue("347"),
    authMethodKey("authMethod"),
    authMethodValue("1.3.6.1.4.1.193.140.1.4"),
    authenticatorKey("authenticator"),
    authenticatorValue("secret"),
    x509nameKey("x509name"),
    x509nameValue("x509testvalue");

    public final static Map<String, String> rolesToTaskProfilesMap = new HashMap();
    private final static String oidRoot = "1.3.6.1.4.1.193.140.2.";
    public final static Map<String, String> caasAuthenticationMaptWithUserID = new HashMap();
    public final static Map<String, String> caasAuthenticationMapWithX509name = new HashMap();
    public final static Map<String, String> caasAuthorizationMap = new HashMap();

    static {
        caasAuthenticationMaptWithUserID.put(queryTypeKey.toString(), AUTHENTICATION.toString());
        caasAuthenticationMaptWithUserID.put(aaqVersionKey.toString(), PROTOCOL_VERSION.toString());
        caasAuthenticationMaptWithUserID.put(sessionIDkey.toString(), sessionIDvalue.toString());
        caasAuthenticationMaptWithUserID.put(userIDkey.toString(), userIDvalue.toString());
        caasAuthenticationMaptWithUserID.put(authenticatorKey.toString(), authenticatorValue.toString());
        caasAuthenticationMaptWithUserID.put(authMethodKey.toString(), authMethodValue.toString());

        caasAuthenticationMapWithX509name.put(queryTypeKey.toString(), AUTHENTICATION.toString());
        caasAuthenticationMapWithX509name.put(aaqVersionKey.toString(), PROTOCOL_VERSION.toString());
        caasAuthenticationMapWithX509name.put(sessionIDkey.toString(), sessionIDvalue.toString());
        caasAuthenticationMapWithX509name.put(x509nameKey.toString(), x509nameValue.toString());
        caasAuthenticationMapWithX509name.put(authenticatorKey.toString(), authenticatorValue.toString());
        caasAuthenticationMapWithX509name.put(authMethodKey.toString(), authMethodValue.toString());

        caasAuthorizationMap.put(queryTypeKey.toString(), AUTHORIZATION.toString());
        caasAuthorizationMap.put(aaqVersionKey.toString(), PROTOCOL_VERSION.toString());
        caasAuthorizationMap.put(sessionIDkey.toString(), sessionIDvalue.toString());
        caasAuthorizationMap.put(userIDkey.toString(), userIDvalue.toString());

        rolesToTaskProfilesMap.put("ReadOnly", oidRoot + "1");
        rolesToTaskProfilesMap.put("CM-Normal", oidRoot + "2");
        rolesToTaskProfilesMap.put("CM-Advanced", oidRoot + "3");
        rolesToTaskProfilesMap.put("unused", oidRoot + "4");
        rolesToTaskProfilesMap.put("FM-Normal", oidRoot + "5");
        rolesToTaskProfilesMap.put("FM-Advanced", oidRoot + "6");
        rolesToTaskProfilesMap.put("PM-Normal", oidRoot + "7");
        rolesToTaskProfilesMap.put("PM-Advanced", oidRoot + "8");
        rolesToTaskProfilesMap.put("SecurityManagment", oidRoot + "9");
        rolesToTaskProfilesMap.put("EricssonSupport", oidRoot + "10");
    }

    private TestConstant(final String value) {
        text = value;
    }

    public final static int OK = 200;
    public final static int BAD_REQUEST = 400;
    public final static int NOT_FOUND = 404;
    private final String text;
    public final static String BASE_URI = "https://localhost:8443/ericsson/servlet/AAService";

    @Override
    public String toString() {
        return text;
    }
}
