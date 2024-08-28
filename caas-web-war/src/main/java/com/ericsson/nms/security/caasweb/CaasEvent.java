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

/**
 * CaasEvent enumeration is containing the CAAS authentication/authorization
 * events.
 *
 * @author edobpet
 */
public enum CaasEvent {

    AUTHETICATION_SUCCESS("AUTHETICATION_SUCCESS"),
    AUTHETICATION_FAILURE("AUTHETICATION_FAILURE"),
    AUTHORIZATION_SUCCESS("AUTHORIZATION_SUCCESS"),
    AUTHORIZATION_FAILURE("AUTHORIZATION_FAILURE"),
    BAD_REQUEST("BAD_REQUEST");

    private CaasEvent(String value) {
        text = value;
    }
    private final String text;

    @Override
    public String toString() {
        return text;
    }
}
