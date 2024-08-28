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
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;

/**
 *
 * @author edobpet
 */
public class CaasParamSyntaxValidatorTest extends TestCase {

    private CaasParamSyntaxValidator paramValidator;
    private final static String queryTypeKey = CaasConstant.queryTypeKey.toString();
    private final String aaqVersionKey = TestConstant.aaqVersionKey.toString();
    private final String PROTOCOL_VERSION = TestConstant.PROTOCOL_VERSION.toString();
    private final String sessionIDkey = TestConstant.sessionIDkey.toString();
    private final String userIDkey = TestConstant.userIDkey.toString();
    private final String x509nameKey = TestConstant.x509nameKey.toString();
    private final String authMethodKey = TestConstant.authMethodKey.toString();
    private final String authenticatorKey = TestConstant.authenticatorKey.toString();
    private final String authenticatorValue = TestConstant.authenticatorValue.toString();
    private final String err = "err";
    private final List<String> caasAuthenticationKeyList = new ArrayList();
    private final List<String> caasAuthorizationKeyList = new ArrayList();
    private List<String> clientAuthenticationKeyList;
    private List<String> clientAuthorizationKeyList;

    @Before
    @Override
    public void setUp() throws Exception {
        paramValidator = new CaasParamSyntaxValidator();
        paramValidator.logger = Mockito.mock(Logger.class);

        caasAuthenticationKeyList.add(queryTypeKey);
        caasAuthenticationKeyList.add(aaqVersionKey);
        caasAuthenticationKeyList.add(sessionIDkey);
        caasAuthenticationKeyList.add(userIDkey);
        caasAuthenticationKeyList.add(authenticatorKey);
        caasAuthenticationKeyList.add(authMethodKey);

        caasAuthorizationKeyList.add(queryTypeKey);
        caasAuthorizationKeyList.add(aaqVersionKey);
        caasAuthorizationKeyList.add(sessionIDkey);
        caasAuthorizationKeyList.add(userIDkey);

        clientAuthenticationKeyList = new ArrayList(caasAuthenticationKeyList);
        clientAuthorizationKeyList = new ArrayList(caasAuthorizationKeyList);
    }

    private void resetClientList(List<String> client, List<String> caas) {
        client = new ArrayList<>(caas);
    }

    /**
     * 1. Test Authentication With Null Parameters.
     *
     * @throws Throwable
     */
    @Test
    public void testAuthenticationWithNullParams1() throws Throwable {
        invokeVeryfyParamsKeysAuthenticationSyntax(null, caasAuthenticationKeyList);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, null);
        invokeVeryfyParamsKeysAuthenticationSyntax(null, null);
    }

    /**
     * 2. Test Invalid Authentication and authorization aaqVersion key.
     *
     * @throws Throwable
     */
    @Test
    public void testInvalidAuthenticationParamAaqVersion2() throws Throwable {
        clientAuthenticationKeyList = modifyList(clientAuthenticationKeyList, aaqVersionKey);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 3. Test Invalid Authentication and authorization SessionId key.
     *
     * @throws Throwable
     */
    @Test
    public void testInvalidAuthenticationParamSessionId3() throws Throwable {
        clientAuthenticationKeyList = modifyList(clientAuthenticationKeyList, sessionIDkey);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 4. Test Invalid Authentication and authorization userID key.
     *
     * @throws Throwable
     */
    @Test
    public void testInvalidAuthenticationParamUserID4() throws Throwable {
        clientAuthenticationKeyList = modifyList(clientAuthenticationKeyList, userIDkey);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 5. Test Invalid Authentication authMethod key.
     *
     * @throws Throwable
     */
    @Test
    public void testInvalidAuthenticationParamAuthMethod5() throws Throwable {
        clientAuthenticationKeyList = modifyList(clientAuthenticationKeyList, authMethodKey);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 6. Test Invalid Authentication authenticator key.
     *
     * @throws Throwable
     */
    @Test
    public void testInvalidAuthenticationParamAuthenticator6() throws Throwable {
        clientAuthenticationKeyList = modifyList(clientAuthenticationKeyList, authenticatorKey);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 7. Test authentication request with valid x509name key only.
     */
    @Test
    public void testAuthenticationWithOnlyValidx509nameKey7() {
        clientAuthenticationKeyList.remove(userIDkey);
        clientAuthenticationKeyList.add(x509nameKey);
        caasAuthenticationKeyList.remove(userIDkey);
        caasAuthenticationKeyList.add(x509nameKey);
        boolean result = paramValidator.veryfyParamsKeysSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        assertTrue(result);
        caasAuthenticationKeyList.remove(x509nameKey);
        caasAuthenticationKeyList.add(userIDkey);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 8. Test authentication request with invalid x509name key.
     *
     * @throws Throwable
     */
    @Test
    public void testAuthenticationInvalidX509nameKey8() throws Throwable {
        clientAuthenticationKeyList.remove(userIDkey);
        clientAuthenticationKeyList.add(x509nameKey + err);
        caasAuthenticationKeyList.remove(userIDkey);
        caasAuthenticationKeyList.add(x509nameKey);
        invokeVeryfyParamsKeysAuthenticationSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        caasAuthenticationKeyList.remove(x509nameKey);
        caasAuthenticationKeyList.add(userIDkey);
        resetClientList(clientAuthenticationKeyList, caasAuthenticationKeyList);
    }

    /**
     * 9. Test authentication request with set of both userID and x509name
     * assuming the tests for key syntax are correct (should fail, because use
     * case is ether one or the other but not both)
     */
    @Test
    public void testValidateUserIDvalueX509nameValue9() {
        assertTrue(paramValidator.validateUserIDvalueX509nameValue(null, x509nameKey));
        assertTrue(paramValidator.validateUserIDvalueX509nameValue(userIDkey, null));
        boolean result = paramValidator.validateUserIDvalueX509nameValue(null, null);
        assertResult(result);
    }

    /**
     * 10. Test validate syntax of aaqVersion value sessionId value.
     */
    @Test
    public void testValidateAaqVersionValueSessionIdValue10() {
        invokeValidateAaqVersionValueSessionIdValue(PROTOCOL_VERSION + err, "347");
        invokeValidateAaqVersionValueSessionIdValue(PROTOCOL_VERSION, null);
    }

    /**
     * 11. Test authentication request with only aaqVersion missing but
     * sessionId exists
     */
    @Test
    public void testRequestWithOnlyAaqVersionMissingButSessionIdExists11() {
        invokeValidateAaqVersionValueSessionIdValue(null, "347");
    }

    /**
     * 12. Test authentication request with only sessionId missing but
     * aaqVersion exists.
     */
    @Test
    public void testRequestWithOnlySessionIdMissingButQaqVersionExists12() {
        invokeValidateAaqVersionValueSessionIdValue(PROTOCOL_VERSION, null);
    }

    /**
     * 13. Test authentication request with userID and x509name both missing.
     */
    @Test
    public void testRequestWithMissingUserIDandX509name13() {
        boolean result = paramValidator.validateUserIDvalueX509nameValue(null, null);
        assertResult(result);
    }

    /**
     * 14. Test authentication request with authMethod missing and valid
     * authenticator
     */
    @Test
    public void testValidateAuthMethodValueAuthenticatorValue14() {
        boolean result = paramValidator.validateAuthMethodValueAuthenticatorValue(null, authenticatorValue);
        assertResult(result);
    }

    /**
     * 15. Test request with null authenticator and valid authMethod.
     */
    @Test
    public void testRequestWithNullAuthenticatorAndValidAuthMethod15() {
        boolean result = paramValidator.validateAuthMethodValueAuthenticatorValue(authMethodKey, null);
        assertResult(result);
    }

    /**
     * 16. Test with invalid authenticator value and valid authMethod key.
     */
    @Test
    public void testInvalidAuthenticatorValueAndValidAuthMethodKey16() {
        boolean result = paramValidator.validateAuthMethodValueAuthenticatorValue(authMethodKey, authenticatorValue + err);
        assertResult(result);
    }

    /**
     * 17. Test with valid authenticator value and valid authMethod key.
     */
    @Test
    public void testValidAuthenticatorValueAndValidAuthMethodKey17() {
        assertTrue(paramValidator.validateAuthMethodValueAuthenticatorValue(authMethodKey, authenticatorValue));
    }

    private void invokeValidateAaqVersionValueSessionIdValue(String aaqVersionValue, String sessionIdValue) {
        boolean result = paramValidator.validateAaqVersionValueSessionIdValue(aaqVersionValue, sessionIdValue);
        assertResult(result);
    }

    private List<String> modifyList(final List<String> list, final String param) {
        for (int i = 0; i < list.size(); ++i) {
            String key = list.get(i);
            if (key.equals(param)) {
                list.set(i, key + err);
            }
        }
        return list;
    }

    private void invokeVeryfyParamsKeysAuthenticationSyntax(
            List<String> clientAuthenticationKeyList,
            List<String> caasAuthenticationKeyList) {

        boolean result = paramValidator.veryfyParamsKeysSyntax(clientAuthenticationKeyList, caasAuthenticationKeyList);
        assertResult(result);
    }

    private void assertResult(boolean result) {
        assertFalse("Invalid request should return false result.", result);
    }
}