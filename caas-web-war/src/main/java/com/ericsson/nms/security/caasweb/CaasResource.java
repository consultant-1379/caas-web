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

import java.security.Principal;
import java.security.cert.X509Certificate;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.slf4j.Logger;

/**
 * CaasResource class is responsible for handling the incoming requests and
 * verify whether the client has provided certificate in the requests headers.
 *
 * @author edobpet
 */
@Path("/")
public class CaasResource {

    @Inject
    protected Logger logger;

    @Context
    private HttpServletRequest request;

    @Inject
    private CaasRequestController controller;

    private final static String userIDKey = CaasConstant.userIDkey.toString();

    public CaasResource() {
    }

    @POST
    @Path("/servlet/AAService")
    @Produces({MediaType.TEXT_PLAIN})
    public Response authenticationAuthorizationQuery() throws WebApplicationException {
        Response response = null;
        Principal nodeSubjectName;

        logger.debug("Request received from node IP " + request.getRemoteAddr());

        final X509Certificate[] certs = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
        if (certs != null) {
            nodeSubjectName = certs[0].getSubjectDN();
            logger.debug("Subject distinguished name of the node: " + nodeSubjectName);
            logger.debug("User attempting to access the NE " + nodeSubjectName + " is : " + request.getParameter(userIDKey));
            response = controller.process(request, nodeSubjectName);
        } else {
            handleError("Authentication is required and has failed. No certificate available in the request.",
                    null,
                    Response.Status.UNAUTHORIZED);
        }
        return response;
    }

    private void handleError(String msg, Throwable ex, Status status) {
        if (ex == null) {
            logger.error(msg);
        } else {
            logger.error(msg, ex);
        }
        throw new WebApplicationException(status);
    }
}
