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

/**
 * CaasLogFormater class is responsible for formating the most essential data
 * associated for each request that is: user ID, node DN (The subject (subject
 * distinguished name) value from the certificate), node IP (The IP address
 * where the request came from).
 *
 * @author edobpet
 */
public class CaasLogFormater {

    protected static String formatAuthentication(
            final String userID,
            final String nodeIP,
            final Principal nodeSubjectName,
            final String allLoids,
            final boolean success) {
        String logMessage = "";
        if (success) {
            logMessage = "User " + userID + " authenticated on host " + nodeIP
                    + " with node id " + nodeSubjectName + "\n" + "Valid profiles: " + allLoids;
        } else {
            logMessage = "User " + userID + " failed authentication on host " + nodeIP
                    + " with node id " + nodeSubjectName;
        }
        return logMessage;
    }

    protected static String formatAuthorization(
            final String userID,
            final String nodeIP,
            final Principal nodeSubjectName,
            final String oids,
            final boolean success) {
        String logMessage;
        if (success) {
            logMessage = "User " + userID + " authorized on host " + nodeIP
                    + " with node id " + nodeSubjectName + "\n" + "Valid profiles: " + oids;
        } else {
            logMessage = "Authorization, no profiles found for user " + userID
                    + " on host " + nodeIP + " with node id " + nodeSubjectName;
        }
        return logMessage;
    }
}
