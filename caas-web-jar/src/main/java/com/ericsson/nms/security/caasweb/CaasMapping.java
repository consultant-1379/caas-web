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
import java.util.Map;

/**
 * CaasMapping enumeration maps the roles to their appropriate OIDs
 * 
 * @author edobpet
 */
public enum CaasMapping {

    ;

    private CaasMapping() {
    }

    public final static Map<String, String> rolesToTaskProfilesMap = new HashMap();
    private final static String oidRoot = "1.3.6.1.4.1.193.140.2.";

    static {
        rolesToTaskProfilesMap.put("ReadOnly", oidRoot + "1");
        rolesToTaskProfilesMap.put("CM-Normal", oidRoot + "2");
        rolesToTaskProfilesMap.put("CM-Advanced", oidRoot + "3");
        rolesToTaskProfilesMap.put("unused", oidRoot + "4");
        rolesToTaskProfilesMap.put("FM-Normal", oidRoot + "5");
        rolesToTaskProfilesMap.put("FM-Advanced", oidRoot + "6");
        rolesToTaskProfilesMap.put("PM-Normal", oidRoot + "7");
        rolesToTaskProfilesMap.put("PM-Advanced", oidRoot + "8");
        rolesToTaskProfilesMap.put("SecurityManagment", oidRoot + "9");
        rolesToTaskProfilesMap.put("EricssonSupport", oidRoot + "10");
    }
}
