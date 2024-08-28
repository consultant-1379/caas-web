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

import java.util.HashMap;

//Help class for parsing response
class ResponseMap extends HashMap<String, String> {

    private static final long serialVersionUID = 1L;

    // Extracts (key,value)-pairs from a string of the format:
    // aaqVersion=0&session-identifier=1&userID=alice&localLookupAllowed=true&localLookupTimeout=60
    ResponseMap(String content) {
        String key, value;

        while (content.indexOf("&") != -1) {
            key = content.substring(content.lastIndexOf("&") + 1, content.length());
            value = key.substring(key.indexOf("=") + 1, key.length());
            key = key.substring(0, key.indexOf("="));
            this.put(key, value);

            content = content.substring(0, content.lastIndexOf("&"));
        }
        value = content.substring(content.indexOf("=") + 1, content.length());
        key = content.substring(0, content.indexOf("="));
        this.put(key, value);
    }
}
