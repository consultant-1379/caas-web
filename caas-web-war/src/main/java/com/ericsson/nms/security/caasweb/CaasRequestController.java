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
import java.util.Collections;
import java.util.List;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import org.slf4j.Logger;

/**
 * CaasRequestController class is responsible for handling the requests from the
 * client and determining the query type (i.e authentication or authorization).
 *
 * @author edobpet
 */
public class CaasRequestController {

    private final static String AUTHENTICATION = CaasConstant.AUTHENTICATION.toString();
    private final static String AUTHORIZATION = CaasConstant.AUTHORIZATION.toString();
    private final static String queryTypeKey = CaasConstant.queryTypeKey.toString();
    private final static String aaqVersionKey = CaasConstant.aaqVersionKey.toString();
    private final static String userIDKey = CaasConstant.userIDkey.toString();
    private final static String sessionIDkey = CaasConstant.sessionIDkey.toString();
    private final static String authMethodKey = CaasConstant.authMethodKey.toString();
    private final static String authenticatorKey = CaasConstant.authenticatorKey.toString();
    private final static String x509nameKey = CaasConstant.x509nameKey.toString();
    private final List<String> caasAuthenticationKeyListWithUserID = CaasConstant.caasAuthenticationKeyListWithUserID;
    private final List<String> caasAuthenticationKeyListWithX509name = CaasConstant.caasAuthenticationKeyListWithX509name;
    private final List<String> caasAuthorizationKeyList = CaasConstant.caasAuthorizationKeyList;
    private final static String CAAS = CaasConstant.CAAS.toString();
    private final static String BAD_REQUEST = CaasEvent.BAD_REQUEST.toString();
    private final static String target = "target is node CN: ";

    @Inject
    protected Logger logger;
    @Inject
    private CaasResponseGenerator responseGenerator;
    @Inject
    SystemRecorder systemRecorder;

    protected Response process(HttpServletRequest request, Principal nodeSubjectName) {

        final String queryTypeValue = request.getParameter(queryTypeKey);
        final String aaqVersionValue = request.getParameter(aaqVersionKey);
        final String userIDvalue = request.getParameter(userIDKey);
        final String sessionIDvalue = request.getParameter(sessionIDkey);
        final String authMethodValue = request.getParameter(authMethodKey);
        final String authenticatorValue = request.getParameter(authenticatorKey);
        final String x509nameValue = request.getParameter(x509nameKey);

        final List<String> clientParamKeys = Collections.list(request.getParameterNames());
        List<String> caasParamKeys = null;
        Response response = null;

        String responseString = null;
        Response.Status status = null;

        final String nodeIP = request.getRemoteAddr();

        if (queryTypeValue != null) {

            if (queryTypeValue.equals(AUTHENTICATION)) {

                if (userIDvalue == null && x509nameValue != null) {
                    caasParamKeys = caasAuthenticationKeyListWithX509name;
                } else if ((userIDvalue != null && x509nameValue == null)) {
                    caasParamKeys = caasAuthenticationKeyListWithUserID;
                } else if ((userIDvalue != null && x509nameValue != null)) {
                    caasParamKeys = new ArrayList(caasAuthenticationKeyListWithUserID);
                    caasParamKeys.add(x509nameKey);
                }

                responseString = responseGenerator.generateAuthenticationResponse(
                        aaqVersionValue,
                        sessionIDvalue,
                        userIDvalue,
                        x509nameValue,
                        authMethodValue,
                        authenticatorValue,
                        nodeIP,
                        clientParamKeys,
                        caasParamKeys,
                        nodeSubjectName);
                status = Response.Status.OK;
                response = initializeResponse(responseString, status);
            } else if (queryTypeValue.equals(AUTHORIZATION)) {

                responseString = responseGenerator.generateAuthorizationResponse(
                        aaqVersionValue,
                        sessionIDvalue,
                        userIDvalue,
                        x509nameValue,
                        clientParamKeys,
                        caasAuthorizationKeyList,
                        nodeSubjectName,
                        nodeIP);
                status = Response.Status.OK;
                response = initializeResponse(responseString, status);
            } else {
                handleError("The request contains incorrect " + queryTypeKey + " parameter.",
                        null,
                        Response.Status.BAD_REQUEST,
                        userIDvalue,
                        nodeIP,
                        nodeSubjectName);
            }
        } else {
            handleError("The request contains incorrect " + queryTypeKey + " parameter.",
                    null,
                    Response.Status.BAD_REQUEST,
                    userIDvalue,
                    nodeIP,
                    nodeSubjectName);
        }
        return response;
    }

    private void handleError(
            String msg,
            Throwable ex,
            Response.Status status,
            String userIDvalue,
            String nodeIP,
            Principal nodeSubjectName) {

        systemRecorder.recordSecurityEvent(
                target + nodeSubjectName,
                CAAS,
                CaasLogFormater.formatAuthentication(userIDvalue, nodeIP, nodeSubjectName, null, false),
                BAD_REQUEST,
                ErrorSeverity.WARNING,
                "FAILURE");
        if (ex == null) {
            logger.warn(msg);
        } else {
            logger.warn(msg, ex);
        }
        throw new WebApplicationException(status);
    }

    private Response initializeResponse(final String responceString, final Response.Status statusCode) {
        Response.ResponseBuilder responseBuilder = null;
        if (responceString != null) {
            responseBuilder = Response.ok(responceString);
        } else {
            responseBuilder = Response.status(statusCode);
        }
        return responseBuilder.build();
    }
}
