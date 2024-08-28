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

import java.util.ArrayList;
import java.util.List;

/**
 * CaasConstant enumeration contains the constants of the AAQ protocol both for
 * input/output key/value pairs
 *
 * @author edobpet
 */
public enum CaasConstant {

    AUTHENTICATION("1.3.6.1.4.1.193.140.1.1"),
    AUTHORIZATION("1.3.6.1.4.1.193.140.1.2"),
    queryTypeKey("queryType"),
    aaqVersionKey("aaqVersion"),
    PROTOCOL_VERSION("0"),
    userIDkey("userID"),
    //to be remove when IDM is deliverd
    userIDvalue("testuser"),
    sessionIDkey("sessionID"),
    authMethodKey("authMethod"),
    authMethodValue("1.3.6.1.4.1.193.140.1.4"),
    //to be remove when IDM is deliverd
    authenticatorKey("authenticator"),
    authenticatorValue("secret"),
    x509nameKey("x509name"),
    x509nameValue("x509testvalue"),
    PROFILE_SEPARATOR(";"),
    success("success"),
    localLookupAllowed("localLookupAllowed"),
    localLookupTimeout("localLookupTimeout"),
    auth_profiles("auth-profiles"),
    session_identifier("session-identifier"),
    CAAS("CPP-based NE Authentication and Authorization Services.");

    public final static List<String> caasAuthenticationKeyListWithUserID = new ArrayList();
    public final static List<String> caasAuthenticationKeyListWithX509name = new ArrayList();
    public final static List<String> caasAuthorizationKeyList = new ArrayList();

    static {
        caasAuthenticationKeyListWithUserID.add(queryTypeKey.toString());
        caasAuthenticationKeyListWithUserID.add(aaqVersionKey.toString());
        caasAuthenticationKeyListWithUserID.add(sessionIDkey.toString());
        caasAuthenticationKeyListWithUserID.add(userIDkey.toString());
        caasAuthenticationKeyListWithUserID.add(authenticatorKey.toString());
        caasAuthenticationKeyListWithUserID.add(authMethodKey.toString());

        caasAuthenticationKeyListWithX509name.add(queryTypeKey.toString());
        caasAuthenticationKeyListWithX509name.add(aaqVersionKey.toString());
        caasAuthenticationKeyListWithX509name.add(sessionIDkey.toString());
        caasAuthenticationKeyListWithX509name.add(x509nameKey.toString());
        caasAuthenticationKeyListWithX509name.add(authenticatorKey.toString());
        caasAuthenticationKeyListWithX509name.add(authMethodKey.toString());

        caasAuthorizationKeyList.add(queryTypeKey.toString());
        caasAuthorizationKeyList.add(aaqVersionKey.toString());
        caasAuthorizationKeyList.add(sessionIDkey.toString());
        caasAuthorizationKeyList.add(userIDkey.toString());
        caasAuthorizationKeyList.add(x509nameKey.toString());
    }

    private CaasConstant(String value) {
        text = value;
    }

    private final String text;

    @Override
    public String toString() {
        return text;
    }
}
