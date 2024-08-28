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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.ejb.Stateless;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.arquillian.junit.InSequence;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.importer.ArchiveImportException;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author edobpet
 */
//@Ignore
@RunWith(Arquillian.class)
@Stateless
public class CaasResourceIntegrationTest {

    static {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(final String hostname, final SSLSession sslSession) {
                return hostname.equals(sslSession.getPeerHost());
            }
        });
    }

    private static final Logger logger = LoggerFactory.getLogger(CaasResourceIntegrationTest.class);
    private final static String earFolder = "../../../caas-web-ear/target/";
    private final static int OK = TestConstant.OK;
    private final static int BAD_REQUEST = TestConstant.BAD_REQUEST;
    private final static int NOT_FOUND = TestConstant.NOT_FOUND;
    private final static String statusMsg400 = "The responce is Non-BAD_REQUEST status";
    private final static String statusMsg200 = "The responce is Non-OK status";
    private final static String AUTHENTICATION = TestConstant.AUTHENTICATION.toString();
    private final static String queryTypeKey = TestConstant.queryTypeKey.toString();
    private final static String userIDkey = TestConstant.userIDkey.toString();
    private final static String userIDvalue = TestConstant.userIDvalue.toString();
    private final static String sessionIDvalue = TestConstant.sessionIDvalue.toString();
    private final static String x509nameKey = TestConstant.x509nameKey.toString();
    private final static String x509nameValue = TestConstant.x509nameValue.toString();
    private final static String authenticatorValue = TestConstant.authenticatorValue.toString();
    private final static String caas_web_client_trustore = TestConstant.caas_web_client_trustore.toString();
    private final static String caas_web_client_keystore = TestConstant.caas_web_client_keystore.toString();
    private final static char[] PASSWORD = TestConstant.PASSWORD.toString().toCharArray();
    public final static Map<String, String> caasAuthenticationMaptWithUserID = TestConstant.caasAuthenticationMaptWithUserID;
    public final static Map<String, String> caasAuthenticationMapWithX509name = TestConstant.caasAuthenticationMapWithX509name;
    public final static Map<String, String> caasAuthorizationMap = TestConstant.caasAuthorizationMap;
    private StringBuilder response;
    private final static String value = "value";
    private final static String key = "key";
    public final static Map<String, String> rolesToTaskProfilesMap = TestConstant.rolesToTaskProfilesMap;
    public final static String PROFILE_SEPARATOR = TestConstant.PROFILE_SEPARATOR.toString();

    @Deployment(name = "caas-web-ear")
    public static Archive<?> createADeployableEAR() {
        return getEar();
    }

    @Deployment(name = "caas-web-test")
    public static Archive<?> createADeployableTestWebarchive() {
        WebArchive archive = ShrinkWrap.create(WebArchive.class, "caas-web-test.war")
                .addAsWebInfResource("META-INF/beans.xml").addClass(TestConstant.class);
        return archive;
    }

    @Before
    public void setCert() {
        setupSecureSSLConnection();
    }

    /**
     * 1. Test Invalid Authentication queryType Key Syntax.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(1)
    public void testInvalidAuthenticationQueryTypeKeySyntax1() throws IOException {
        String requestParams = modifyKeyRequestParams(new HashMap(caasAuthenticationMaptWithUserID), queryTypeKey, key, "error");
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 2. Test Invalid Authentication queryType Value Syntax
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(2)
    public void testAuthenticationQueryTypeValueSyntax2() throws IOException {
        String requestParams = modifyKeyRequestParams(new HashMap(caasAuthenticationMaptWithUserID), AUTHENTICATION, value, "error");
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 3. Test authentication request with valid x509name key only. (expected
     * successful request but use x509name in the response)
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(3)
    public void testAuthenticationWithOnlyValidX509nameKey3() throws IOException {
        String requestParams = modifyKeyRequestParams(caasAuthenticationMapWithX509name, AUTHENTICATION, null, null);
        assertTrue(statusMsg200, post(requestParams, TestConstant.BASE_URI) == OK);
        assertNotNull("response string from CAAS is null.", response);
        ResponseMap rm = new ResponseMap(response.toString());
        assertEquals("Authentication request has failed.", "true", rm.get("success"));
        assertTrue("The AAQ response string does not contain the key: " + x509nameKey, rm.containsKey(x509nameKey));
        assertEquals("The value of the key " + x509nameKey + "  is invalid.", x509nameValue, rm.get(x509nameKey));
    }

    /**
     * 4. Test authentication request with invalid x509name key.
     *
     * @throws java.io.IOException
     */
    //TODO troubleshoot
//    @Test
//    @RunAsClient
    @InSequence(4)
    public void testAuthenticationInvalidX509nameKey4() throws IOException {
        String requestParams = modifyKeyRequestParams(new HashMap(caasAuthenticationMaptWithUserID), x509nameKey, key, "error");
        System.out.println("\n\t testAuthenticationInvalidX509nameKey4() requestParams: " + requestParams);
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 5.Test if the sessionID value is a invalid integer.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(5)
    public void testAuthenticationInvalidSessionIDValueIsInteger5() throws IOException {
        String requestParams = modifyKeyRequestParams(new HashMap(caasAuthenticationMaptWithUserID), sessionIDvalue, value, "error");
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 6. Test if the sessionID value is too big positive integer.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(6)
    public void testAuthenticationInvalidSessionIDValueIsTooBigInteger6() throws IOException {
        String requestParams = modifyKeyRequestParams(new HashMap(caasAuthenticationMaptWithUserID), sessionIDvalue, value, Integer.MAX_VALUE + "1");
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 7. Test if the sessionID value is negative integer.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(7)
    public void testAuthenticationInvalidSessionIDValueIsNegativeInteger7() throws IOException {
        String requestParams = modifyKeyRequestParams(new HashMap(caasAuthenticationMaptWithUserID), sessionIDvalue, value, "-" + sessionIDvalue);
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 8. Test authentication request with missing queryType.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(8)
    public void testRequestWithMissingQueryType8() throws IOException {
        Map tempMap = new HashMap(caasAuthenticationMaptWithUserID);
        tempMap.remove(queryTypeKey);
        String requestParams = modifyKeyRequestParams(tempMap, null, null, null);
        assertTrue(statusMsg400, post(requestParams, TestConstant.BASE_URI) == BAD_REQUEST);
    }

    /**
     * 9. Test authentication request with userID and x509name (successful
     * request but use userID in the response)
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(9)
    public void testValidRequestWithUserIDinTheResponse9() throws IOException {
        Map tempMap = new HashMap(caasAuthenticationMaptWithUserID);
        tempMap.put(x509nameKey, x509nameValue);
        String requestParams = modifyKeyRequestParams(tempMap, null, null, null);
        int resp = post(requestParams, TestConstant.BASE_URI);
        assertTrue(statusMsg200, resp == OK);
        assertNotNull("response string from CAAS is null.", response);
        ResponseMap rm = new ResponseMap(response.toString());
        assertEquals("Authentication request has failed.", "true", rm.get("success"));
        assertTrue("The AAQ response string does not contain the key: " + userIDkey, rm.containsKey(userIDkey));
        assertEquals("The value of the key " + x509nameKey + "  is invalid.", userIDvalue, rm.get(userIDkey));
        assertNull(rm.get(x509nameKey));
    }

    /**
     * 10. Test valid authorization request.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(10)
    public void testValidAuthorizationRequest10() throws IOException {
        String requestParams = modifyKeyRequestParams(caasAuthorizationMap, null, null, null);
        assertTrue(statusMsg200, post(requestParams, TestConstant.BASE_URI) == OK);
        ResponseMap rm = new ResponseMap(response.toString());
        assertEquals("Authorization request has failed.", "true", rm.get("success"));
        assertTrue("The AAQ response string does not contain the key: " + userIDkey, rm.containsKey(userIDkey));
    }

    /**
     * 11. Test invalid URL request.
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(11)
    public void testInvalidURL11() throws IOException {
        String requestParams = modifyKeyRequestParams(caasAuthenticationMaptWithUserID, null, null, null);
        assertTrue("Non-" + NOT_FOUND + " code", post(requestParams, TestConstant.BASE_URI + "/wrong/uri") == NOT_FOUND);
    }

    /**
     * 12. Test the OIDs values returned are valid (Authentication).
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(12)
    public void testValidOIDs12() throws IOException {
        String requestParams = modifyKeyRequestParams(caasAuthenticationMaptWithUserID, null, null, null);
        assertTrue("Non-" + OK + " code", post(requestParams, TestConstant.BASE_URI) == OK);
        assertNotNull("response string from CAAS is null.", response);
        ResponseMap rm = new ResponseMap(response.toString());
        assertEquals("Authorization request has failed.", "true", rm.get("success"));
        String oids = rm.get("auth-profiles");
        assertNotNull("auth-profiles key has no OIDs values in the response map.", oids);
        String[] oidsArr = oids.split(PROFILE_SEPARATOR);
        for (String oid : oidsArr) {
            assertTrue("OID value " + oid + " returned from CAAS response is not valid.", rolesToTaskProfilesMap.containsValue(oid));
        }
    }

    /**
     * 13. Test the OIDs values returned are valid (Authorization).
     *
     * @throws java.io.IOException
     */
    @Test
    @RunAsClient
    @InSequence(13)
    public void testValidOIDs13() throws IOException {
        String requestParams = modifyKeyRequestParams(caasAuthorizationMap, null, null, null);
        assertTrue("Non-" + OK + " code", post(requestParams, TestConstant.BASE_URI) == OK);
        assertNotNull("response string from CAAS is null.", response);
        ResponseMap rm = new ResponseMap(response.toString());
        assertEquals("Authorization request has failed.", "true", rm.get("success"));

        String oids = rm.get("auth-profiles");
        assertNotNull("auth-profiles key has no OIDs values in the response map.", oids);
        String[] oidsArr = oids.split(PROFILE_SEPARATOR);
        for (String oid : oidsArr) {
            assertTrue("OID value " + oid + " returned from CAAS response is not valid.", rolesToTaskProfilesMap.containsValue(oid));
        }
    }

    /**
     * 14. Test valid authentication with incorrect password.
     */
    @Test
    @RunAsClient
    @InSequence(14)
    public void testValidAuthenticationWithIncorrectPassword14() throws IOException {
        String requestParams = modifyKeyRequestParams(caasAuthenticationMaptWithUserID, authenticatorValue, value, "error");
        assertTrue("Non-" + OK + " code", post(requestParams, TestConstant.BASE_URI) == OK);
        assertNotNull("response string from CAAS is null.", response);
        ResponseMap rm = new ResponseMap(response.toString());
        assertTrue("The response string should contain success key.", rm.containsKey("success"));
        assertEquals("Authentication response string should contain success=false when using incorrect password, but it contained success=false.",
                "false", rm.get("success"));
    }

    /**
     * 15. Test valid authorization for inexisting user.
     */
//    @Test
//    @RunAsClient
//    public void testValidAuthorizationForInexistingUser15() {
//
//    }
    private int post(String aaqParams, String caasURL) throws MalformedURLException, IOException {

        response = null;
        int responseCode = 0;
        URL url = new URL(caasURL);

        //System.out.println("\n\t caasURL: " + caasURL);
        HttpsURLConnection httpsCon = (HttpsURLConnection) url.openConnection();
        httpsCon.setRequestMethod("POST");
        httpsCon.setDoOutput(true);
        httpsCon.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        try (DataOutputStream wr = new DataOutputStream(httpsCon.getOutputStream())) {
            wr.writeBytes(aaqParams.toString());
            wr.flush();
        }

        responseCode = httpsCon.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(httpsCon.getInputStream()))) {
                String inputLine;
                response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                httpsCon.disconnect();
            }
        } else if (responseCode == HttpURLConnection.HTTP_BAD_REQUEST) {
            return responseCode;
        } else {
            logger.error("Unsupported HTTP code received: " + responseCode);
        }
        return responseCode;
    }

    /**
     * @param copyMap The map to be used in order to build the string of query
     * parameters for the post request.
     * @param currentKeyValue The
     * @param type The type of the parameter to be changed (key or value).
     * @param error The error string to be added to the target key/value.
     * @return Return the build post request string.
     */
    private String modifyKeyRequestParams(Map<String, String> map, final String currentKeyValue, final String type, final String error) {
        StringBuilder aaqParams = new StringBuilder("");
        String oldKey = null;
        String oldValue = null;
        String newKey = "";

        if (type != null) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                oldKey = entry.getKey();
                oldValue = entry.getValue();

                if (type.equals(value)) {
                    if (oldValue.equals(currentKeyValue)) {
                        oldValue += error;
                        break;
                    }
                } else if (type.equals(key)) {
                    if (oldKey.equals(currentKeyValue)) {
                        newKey = oldKey + error;
                        break;
                    }
                }
            }

            map.remove(oldKey);
            if (type.equals(key)) {
                map.put(newKey, oldValue);
            } else if (type.equals(value)) {
                map.put(oldKey, oldValue);
            }
        }

        for (Map.Entry<String, String> entry : map.entrySet()) {
            oldKey = entry.getKey();
            oldValue = entry.getValue();
            aaqParams.append(oldKey).append("=").append(oldValue).append("&");
        }
        aaqParams.deleteCharAt(aaqParams.length() - 1);
        return aaqParams.toString();
    }

    private static Archive<?> getEar() {
        File earDir = new File(earFolder);
        EnterpriseArchive archive = null;
        for (File file : earDir.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".ear")) {
                try {
                    archive = ShrinkWrap.createFromZipFile(EnterpriseArchive.class, file);
                } catch (IllegalArgumentException | ArchiveImportException ex) {
                    logger.error(ex.getMessage(), ex);
                }
            }
        }
        if (archive == null) {
            logger.error("Cass web ear file does not exist. Run mvn clean install");
        }
        return archive;
    }

    private void setupSecureSSLConnection() {
        TrustManager mytm[] = null;
        KeyManager mykm[] = null;
        final String protocol = "SSL";
        File caasWebClientTrustoreFile = new File(caas_web_client_trustore);
        File caasWebClientKeystoreFile = new File(caas_web_client_keystore);
        if (caasWebClientTrustoreFile.exists() && caasWebClientTrustoreFile.exists()) {
            try {
                mytm = new TrustManager[]{new CaasX509TrustManager(caas_web_client_trustore, PASSWORD)};
                mykm = new KeyManager[]{new CaasX509KeyManager(caas_web_client_keystore, PASSWORD)};
                SSLContext context = null;
                try {
                    context = SSLContext.getInstance(protocol);
                    context.init(mykm, mytm, null);
                } catch (NoSuchAlgorithmException ex) {
                    logger.error("No Provider supports a TrustManagerFactorySpi implementation for the specified protocol.", ex);
                } catch (KeyManagementException ex) {
                    logger.error("SSL context for this connection was not initialized.", ex);
                }
                context.init(mykm, mytm, null);
                HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());
            } catch (Exception ex) {
                logger.error("Certificate for client was not loaded.", ex);
            }
        } else {
            logger.error(caas_web_client_trustore + " or " + caasWebClientKeystoreFile + " do not exist.");
            fail();
        }
    }

    class CaasX509TrustManager implements X509TrustManager {

        /*
         * The default PKIX X509TrustManager9.  We'll delegate
         * decisions to it, and fall back to the logic in this class if the
         * default X509TrustManager doesn't trust it.
         */
        X509TrustManager pkixTrustManager;

        CaasX509TrustManager(String trustStore, char[] password) throws Exception {
            this(new File(trustStore), password);
        }

        CaasX509TrustManager(File trustStore, char[] password) throws Exception {
            // create a "default" JSSE X509TrustManager.

            KeyStore ks = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream(trustStore), password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(ks);

            TrustManager tms[] = tmf.getTrustManagers();
            for (TrustManager tm : tms) {
                if (tm instanceof X509TrustManager) {
                    pkixTrustManager = (X509TrustManager) tm;
                    return;
                }
            }
            throw new Exception("Couldn't initialize");
        }

        /*
         * Delegate to the default trust manager.
         */
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            try {
                pkixTrustManager.checkClientTrusted(chain, authType);
            } catch (CertificateException excep) {
                //excep.printStackTrace();
            }
        }

        /*
         * Delegate to the default trust manager.
         */
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            try {
                pkixTrustManager.checkServerTrusted(chain, authType);
            } catch (CertificateException excep) {
                //excep.printStackTrace();
            }
        }

        /*
         * Merely pass this through.
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return pkixTrustManager.getAcceptedIssuers();
        }
    }

    class CaasX509KeyManager implements X509KeyManager {

        X509KeyManager pkixKeyManager;

        CaasX509KeyManager(String keyStore, char[] password) throws Exception {
            this(new File(keyStore), password);
        }

        CaasX509KeyManager(File keyStore, char[] password) throws Exception {
            // create a "default" JSSE X509KeyManager.

            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keyStore), password);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
            kmf.init(ks, password);

            KeyManager kms[] = kmf.getKeyManagers();
            for (KeyManager km : kms) {
                if (km instanceof X509KeyManager) {
                    pkixKeyManager = (X509KeyManager) km;
                    return;
                }
            }

            /*
             * Find some other way to initialize, or else we have to fail the
             * constructor.
             */
            throw new Exception("Couldn't initialize");
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return pkixKeyManager.getPrivateKey(alias);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return pkixKeyManager.getCertificateChain(alias);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return pkixKeyManager.getClientAliases(keyType, issuers);
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return pkixKeyManager.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return pkixKeyManager.getServerAliases(keyType, issuers);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return pkixKeyManager.chooseServerAlias(keyType, issuers, socket);
        }
    }

}
