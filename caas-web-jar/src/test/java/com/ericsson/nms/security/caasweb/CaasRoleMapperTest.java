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
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;

/**
 *
 * @author edobpet
 */
public class CaasRoleMapperTest extends TestCase {

    private CaasRoleMapper roleMapper;
    private final static Map<String, String> map = TestRoleMapping.rolesToTaskProfilesMap;

    public CaasRoleMapperTest() {
    }

    @Before
    @Override
    public void setUp() {
        roleMapper = new CaasRoleMapper();
        roleMapper.logger = Mockito.mock(Logger.class);
    }

    /**
     * 1. Test that all roles are valid.
     */
    @Test
    public void testAllRolesAreValid1() {
        for (String key : map.keySet()) {
            assertNotNull(roleMapper.mapRoleToOID(key));
        }
    }

    /**
     * 2. Test that invalid roles are ignored.
     */
    @Test
    public void testInvalidRolesAreIgnored2() {
        for (String key : map.keySet()) {
            assertNull(roleMapper.mapRoleToOID("invalid" + key));
        }
    }

    /**
     * 3. Test that valid roles are returning valid OIDs.
     */
    @Test
    public void testValidRolesValidOIDs3() {
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            String oid = roleMapper.mapRoleToOID(key);
            assertEquals(value, oid);
        }
    }
}
