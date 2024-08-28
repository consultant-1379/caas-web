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

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;

/**
 * CaasResponseGenerator class is responsible for constructing the response
 * string as defined by AAQ protocol in 2/155 16-105/CSX 101 09 Uen document.
 *
 * @author edobpet
 */
public class CaasResponseGenerator {

    private final static String aaqVersionKey = CaasConstant.aaqVersionKey.toString();
    private final static String PROFILE_SEPARATOR = CaasConstant.PROFILE_SEPARATOR.toString();
    private final static String success = CaasConstant.success.toString();
    private final static String localLookupAllowed = CaasConstant.localLookupAllowed.toString();
    private final static String auth_profiles = CaasConstant.auth_profiles.toString();
    private final static String localLookupTimeout = CaasConstant.localLookupTimeout.toString();
    private final static String session_identifier = CaasConstant.session_identifier.toString();
    private final static String userIDkey = CaasConstant.userIDkey.toString();
    private final static String x509nameKey = CaasConstant.x509nameKey.toString();
    private final static String AUTHETICATION_SUCCESS = CaasEvent.AUTHETICATION_SUCCESS.toString();
    private final static String AUTHETICATION_FAILURE = CaasEvent.AUTHETICATION_FAILURE.toString();
    private final static String AUTHORIZATION_SUCCESS = CaasEvent.AUTHORIZATION_SUCCESS.toString();
    private final static String AUTHORIZATION_FAILURE = CaasEvent.AUTHORIZATION_FAILURE.toString();
    private final static String CAAS = CaasConstant.CAAS.toString();
    private final static String target = "target is node CN: ";
    private String BAD_REQUEST = CaasEvent.BAD_REQUEST.toString();

    //TODO Test mutriple strings writing to the same variable
    private StringBuilder response;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    private Logger logger;

    @Inject
    protected IDMProxy idmProxy;

    @Inject
    private CaasParamSyntaxValidator paramValidator;

    public CaasResponseGenerator() {
    }

    /**
     * Assembles an authentication response string which is to be sent back to
     * the client.
     *
     * @param aaqVersionValue
     * @param sessionIdValue
     * @param userIDvalue
     * @param x509nameValue
     * @param authMethodValue
     * @param authenticatorValue
     * @param nodeIP
     * @param clientParamKeys
     * @param caasParamKeys
     * @param nodeSubjectName
     * @return String The AAQ response string
     * @throws WebApplicationException
     */
    protected String generateAuthenticationResponse(
            final String aaqVersionValue,
            final String sessionIdValue,
            final String userIDvalue,
            final String x509nameValue,
            final String authMethodValue,
            final String authenticatorValue,
            final String nodeIP,
            final List<String> clientParamKeys,
            final List<String> caasParamKeys,
            final Principal nodeSubjectName) throws WebApplicationException {

        response = new StringBuilder("");
        if (paramValidator.veryfyParamsKeysSyntax(clientParamKeys, caasParamKeys)
                //                && paramValidator.validateAuthMethodValueAuthenticatorValue(authMethodValue, authenticatorValue)
                && paramValidator.validateUserIDvalueX509nameValue(userIDvalue, x509nameValue)
                && paramValidator.validateAaqVersionValueSessionIdValue(aaqVersionValue, sessionIdValue)) {

            List<String> listOIDs = null;

            appendResponseId(aaqVersionValue, sessionIdValue);
            appendUserId(userIDvalue, x509nameValue);

            final boolean authenticated = paramValidator.validateAuthMethodValueAuthenticatorValue(authMethodValue, authenticatorValue);
            //TODO
            // verify that authentication is seccess before getting the oids values and determine status based on authetication against LDAP or whatever resource
            if (authenticated) {
                listOIDs = idmProxy.authenticateAndAuthorize(userIDvalue, authMethodValue, authenticatorValue.toCharArray(), nodeSubjectName);
            } else {
                listOIDs = new ArrayList<>();
            }

            setLocalLookupTime();
            response.append(success).append("=").append(authenticated).append("&");
            String allOIDs = appendOIDs(listOIDs);

            if (authenticated) {
                String logMsg = "";
                systemRecorder.recordSecurityEvent(
                        target + nodeSubjectName,
                        CAAS,
                        CaasLogFormater.formatAuthentication(userIDvalue, nodeIP, nodeSubjectName, allOIDs, authenticated),
                        AUTHETICATION_SUCCESS,
                        ErrorSeverity.INFORMATIONAL,
                        "SUCCESS");

                if (allOIDs.equals("")) {
                    // Log successful authentication but no valid profiles
                    logMsg = "Successful authentication, but no valid profiles available.";
                } else {
                    // Log successful authentication
                    logMsg = "Successful authentication with valid profiles: " + allOIDs + ".";
                }
                logger.info(logMsg + CaasLogFormater.formatAuthentication(userIDvalue, nodeIP, nodeSubjectName, allOIDs, authenticated));
            } else {
                response.append(auth_profiles).append("=");
                // Log failed authentication
                systemRecorder.recordSecurityEvent(
                        target + nodeSubjectName,
                        CAAS,
                        CaasLogFormater.formatAuthentication(userIDvalue, nodeIP, nodeSubjectName, null, authenticated),
                        AUTHETICATION_FAILURE,
                        ErrorSeverity.INFORMATIONAL,
                        "FAILURE");

                logger.info("Failed authentication for user " + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName);
            }
        } else {
            systemRecorder.recordSecurityEvent(
                    target + nodeSubjectName,
                    CAAS,
                    "The Authentication parameters for user ID " + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName + " are invalid",
                    BAD_REQUEST,
                    ErrorSeverity.WARNING,
                    "FAILURE");
            logger.debug(BAD_REQUEST + " event on authentication for user " + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName);
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        return response.toString();
    }

    /**
     * Assembles an authorization response string to send back to the client.
     *
     * @param aaqVersionValue
     * @param sessionIdValue
     * @param userIDvalue
     * @param x509nameValue
     * @param clientParamKeys
     * @param caasParamKeys
     * @param nodeSubjectName
     * @param nodeIP
     * @return
     */
    protected String generateAuthorizationResponse(
            final String aaqVersionValue,
            final String sessionIdValue,
            final String userIDvalue,
            final String x509nameValue,
            final List<String> clientParamKeys,
            final List<String> caasParamKeys,
            final Principal nodeSubjectName,
            final String nodeIP) throws WebApplicationException {

        response = new StringBuilder("");
        if (paramValidator.veryfyParamsKeysSyntax(clientParamKeys, caasParamKeys)
                && paramValidator.validateAaqVersionValueSessionIdValue(aaqVersionValue, sessionIdValue)) {

            appendResponseId(aaqVersionValue, sessionIdValue);
            appendUserId(userIDvalue, x509nameValue);
            setLocalLookupTime();
            response.append(success).append("=true&");

            //TODO
            // verify that authentication is seccess before getting the oids values and determine status based on authetication against LDAP or whatever resource
            List<String> listOIDs = idmProxy.authorize(userIDvalue, nodeSubjectName);

            String allOIDs = appendOIDs(listOIDs);

            if (allOIDs.equals("")) {
                // Log failed authorization
                systemRecorder.recordSecurityEvent(
                        target + nodeSubjectName,
                        CAAS,
                        CaasLogFormater.formatAuthorization(userIDvalue, nodeIP, nodeSubjectName, allOIDs, false),
                        AUTHORIZATION_FAILURE,
                        ErrorSeverity.INFORMATIONAL,
                        "FAILURE");
                logger.info("Failed authorization for user " + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName);
            } else {
                // Log successful authorization
                systemRecorder.recordSecurityEvent(
                        target + nodeSubjectName,
                        CAAS,
                        CaasLogFormater.formatAuthorization(userIDvalue, nodeIP, nodeSubjectName, allOIDs, true),
                        AUTHORIZATION_SUCCESS,
                        ErrorSeverity.INFORMATIONAL,
                        "SUCCESS");

                logger.info("Successful authorization for user" + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName);
            }
        } else {
            systemRecorder.recordSecurityEvent(
                    target + nodeSubjectName,
                    CAAS,
                    BAD_REQUEST + " event on authorization for user " + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName,
                    BAD_REQUEST,
                    ErrorSeverity.WARNING,
                    "FAILURE");
            logger.debug(BAD_REQUEST + " event on authorization for user " + userIDvalue + " on node IP: " + nodeIP + " with node subject name: " + nodeSubjectName);
            throw new WebApplicationException(Response.Status.BAD_REQUEST);
        }
        return response.toString();
    }

    private void setLocalLookupTime() {
        //TODO improve the timeout to be configurable...to be decided!
        long authorizationCacheTimeOut = 60;

        if (authorizationCacheTimeOut > 0) {
            response.append(localLookupAllowed).append("=true&");
        } else {
            response.append(localLookupAllowed).append("=false&");
        }
        response.append(localLookupTimeout).append("=").append(authorizationCacheTimeOut).append("&");
    }

    private void appendUserId(final String userIDvalue, final String x509nameValue) {
        if (userIDvalue != null) {
            response.append(userIDkey).append("=").append(userIDvalue).append("&");
        } else {
            response.append(x509nameKey).append("=").append(x509nameValue).append("&");
        }
    }

    private String appendOIDs(final List<String> authorityProfiles) {

        StringBuilder profilesStrBuilder = new StringBuilder("");
        for (Iterator<String> itr = authorityProfiles.iterator(); itr.hasNext();) {
            String profile = itr.next();
            if (!itr.hasNext()) {
                profilesStrBuilder.append(profile);
                break;
            }
            profilesStrBuilder.append(profile + PROFILE_SEPARATOR);
        }

        String profiles = profilesStrBuilder.toString();
        response.append(auth_profiles).append("=").append(profiles);
        return profiles;
    }

    private void appendResponseId(final String aaqVersionValue, final String sessionIdValue) throws WebApplicationException {
        response.append(aaqVersionKey).append("=").append(aaqVersionValue).append("&");
        response.append(session_identifier).append("=").append(sessionIdValue).append("&");
    }
}
