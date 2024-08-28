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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;

/**
 * IDMProxy class is responsible for interacting with LDAP, DPS and IDM to
 * return a list of valid OIDs to the NE initiated the request.
 *
 * @author edobpet
 */
public class IDMProxy {

    @Inject
    private CaasRoleMapper roleMapper;

    //TODO remove the usage of the map directly after role(s) is provided by IDM
    private final static Map<String, String> map = CaasMapping.rolesToTaskProfilesMap;

    public List<String> authenticateAndAuthorize(
            final String userIDvalue,
            final String authMethodValue,
            final char[] authenticatorValue,
            final Principal nodeSubjectName) {

// TODO to be confirmed
//1.	Caas receives NE request and ask for verification for the NE’s  user/password to openDJ. I assume it returns true or false. Is this correct?
//2.	Caas goes to DPS with the valid  user/password.  It receives a list of the TargetGroup(s) as a List<String> from DPS this user belongs to.
//3.	Caas goes to IDM and provides the userID and the list of TargetGroup(s). IDM returns a list of TaskProfiles as a List<String> data structure.
//4.	Caas maps the of TaskProfiles as a List<String> to their appropriate OID and appends them to the profiles field in the response string.
//TODO return all OID : to be removed
//
        return new ArrayList<>(map.values());
    }

    public List<String> authorize(
            String userIDvalue, 
            Principal nodeSubjectName) {
        return new ArrayList<>(map.values());
    }

}
