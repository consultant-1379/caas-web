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

import java.net.URI;
import javax.ws.rs.core.UriBuilder;

/**
 *
 * @author edobpet
 */
public enum TestConstant {

    AUTHENTICATION("1.3.6.1.4.1.193.140.1.1"),
    AUTHORIZATION("1.3.6.1.4.1.193.140.1.2"),
    certFolder("src/main/resources/"),
    PROTOCOL_VERSION("0"),
    //PROFILE_SEPARATOR(";"),
    caas_web_client_keystore(certFolder + "caas-web-client-keystore.jks"),
    caas_web_client_trustore(certFolder + "caas-web-client-trustore"),
    caas_web_server_keystore(certFolder + "caas-web-server-keystore.jks"),
    caas_web_server_trustore(certFolder + "caas-web-server-trustore"),
    PASSWORD("changeit"),
    //ALIAS("caas-web"),
    resourcePackages("com.ericsson.nms.security.caasweb;com.ericsson.oss.itpf.rest"),
    servlet_aaq("servlet/AAService/"),
    queryTypeKey("queryType"),
    aaqVersionKey("aaqVersion"),
    userIDkey("userID"),
    //to be remove when IDM is deliverd
    userIDvalue("testuser"),
    sessionIDkey("sessionID"),
    authMethodKey("authMethod"),
    authMethodValue("1.3.6.1.4.1.193.140.1.4"),
    authenticatorKey("authenticator"),
    authenticatorValue("secret"),
    x509nameKey("x509name"),
    x509nameValue("x509testvalue");
    
    
    private TestConstant(final String value) {
        text = value;
    }

    public final static int OK = 200;
    public final static int BAD_REQUEST = 400;
    public static final URI BASE_URI = getBaseURI();
    private final String text;
    private static final int port = 50142;
    private static final String uri = "https://localhost/";

    @Override
    public String toString() {
        return text;
    }

    private static URI getBaseURI() {
        return UriBuilder.fromUri(uri).port(getPort(port)).build();
    }

    private static int getPort(int defaultPort) {
        String jerseyPort = System.getProperty("jersey.test.port");
        if (null != jerseyPort) {
            try {
                return Integer.parseInt(jerseyPort);
            } catch (NumberFormatException e) {
            }
        }
        return defaultPort;
    }
}
