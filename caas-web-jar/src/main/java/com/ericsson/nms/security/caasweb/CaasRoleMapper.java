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

import java.util.Map;
import javax.inject.Inject;
import org.slf4j.Logger;

/**
 * CaasRoleMapper class is responsible to resolve the OID by give role.
 *
 * @author edobpet
 */
public class CaasRoleMapper {

    private final Map<String, String> map = CaasMapping.rolesToTaskProfilesMap;

    @Inject
    protected Logger logger;

    protected String mapRoleToOID(String role) {
        if (!map.containsKey(role)) {
            logger.error("Role " + role + " is invalid.");
        }
        return map.get(role);
    }

}
