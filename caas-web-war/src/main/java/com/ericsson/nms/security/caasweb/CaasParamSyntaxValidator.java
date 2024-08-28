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

import java.util.Iterator;
import java.util.List;
import javax.inject.Inject;
import org.slf4j.Logger;

/**
 * CaasParamSyntaxValidator class is responsible for validating the syntax of
 * the AAQ key/value pairs passed in by the client's HTTPs post request before
 * processing.
 *
 * @author edobpet
 */
public class CaasParamSyntaxValidator {

    @Inject
    protected Logger logger;
    private final String msg = " contain missing or invalid value(s).";
    private final static String userIDkey = CaasConstant.userIDkey.toString();
    private final static String aaqVersionKey = CaasConstant.aaqVersionKey.toString();
    private final static String x509nameKey = CaasConstant.x509nameKey.toString();
    private final static String sessionIDkey = CaasConstant.sessionIDkey.toString();
    private final static String PROTOCOL_VERSION = CaasConstant.PROTOCOL_VERSION.toString();
    private final static String authMethodKey = CaasConstant.authMethodValue.toString();
    private final static String authenticatorKey = CaasConstant.authenticatorValue.toString();
    private final static String authenticatorVal = CaasConstant.authenticatorValue.toString();

    /**
     * Verify if the set of client's key parameters have valid syntax.
     *
     * @param clientKeyParameters The client's key parameters passed by the
     * request.
     * @param list The authentication or authorization list of expected key
     * parameters.
     * @return
     */
    protected boolean veryfyParamsKeysSyntax(final List<String> clientKeyParameters, final List<String> list) {
        boolean valid = true;
        if (clientKeyParameters != null && list != null) {
            if (!clientKeyParameters.isEmpty()) {
                if (!list.isEmpty()) {
                    for (Iterator<String> key = clientKeyParameters.iterator(); key.hasNext();) {
                        final String paramKey = key.next();
                        if (!list.contains(paramKey)) {
                            valid = handleError(paramKey + " is invalid request parameter.", null);
                        }
                    }
                } else {
                    valid = handleError("CAAS internal list of request params is empty.", null);
                }
            } else {
                valid = handleError("The list of request params is null.", null);
            }
        } else {
            valid = handleError("The list of client's request parameters is null or " + userIDkey + " and " + x509nameKey
                    + " values are missing.", null);
        }
        return valid;
    }

    protected boolean validateUserIDvalueX509nameValue(String userIDvalue, String x509nameValue) {
        boolean result = true;
        if (userIDvalue == null && x509nameValue == null) {
            result = handleError(userIDkey + " and " + x509nameKey + msg, null);
        }
        return result;
    }

    protected boolean validateAaqVersionValueSessionIdValue(String aaqVersionValue, String sessionIdValue) {
        boolean result = true;
        if (aaqVersionValue == null || sessionIdValue == null) {
            result = handleError(aaqVersionKey + " or " + sessionIDkey + msg, null);
        } else {
            if (!aaqVersionValue.equals(PROTOCOL_VERSION)) {
                result = handleError(aaqVersionKey + " or " + sessionIDkey + msg, null);
            }
            try {
                int sessionIdVal = Integer.parseInt(sessionIdValue);
                if (sessionIdVal < 0) {
                    result = handleError(sessionIDkey + " cannot have a negative value " + sessionIdValue + ".", null);
                }
            } catch (NumberFormatException ex) {
                result = handleError(sessionIDkey + " contains invalid integer value.", ex);
            }
        }
        return result;
    }

    protected boolean validateAuthMethodValueAuthenticatorValue(String authMethodValue, String authenticatorValue) {
        boolean result = true;
        if (authMethodValue == null || authenticatorValue == null) {
            result = handleError(authMethodKey + " or " + authenticatorKey + msg, null);
        } else {
            //TODO
            //authenticate the user's password agains LDAP
            //remove hardcoded password when LDAP binding is available           
            if (authMethodValue != null && !authenticatorValue.equals(authenticatorVal)) {
                logger.warn("Authenticator contains invalid password.");
                result = false;
            }
        }
        return result;
    }

    private boolean handleError(String msg, Throwable ex) {
        if (ex == null) {
            logger.warn(msg);
        } else {
            logger.warn(msg, ex);
        }
        return false;
    }
}
