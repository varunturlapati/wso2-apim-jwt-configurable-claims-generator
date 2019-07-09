package com.roblox.rcs;


import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.apimgt.keymgt.service.TokenValidationContext;
import org.wso2.carbon.apimgt.keymgt.token.JWTGenerator;


public class RobloxTokenGenerator extends JWTGenerator {
	
    private final long TIME_OFFSET_MS = 300000;	//For 300 seconds
    private static final Log log = LogFactory.getLog(RobloxTokenGenerator.class);
    
    @Override
    public Map<String, String> populateStandardClaims(TokenValidationContext validationContext) throws APIManagementException {
        Map<String, String> standardClaims = super.populateStandardClaims(validationContext);
        System.out.println("ROBLOX CUSTOM TOKEN GENERATOR - beginning of overriding standard claims");
        log.info("Overriding standard claims. Adding fields 'nbf' and 'iat'");
        long currTime = System.currentTimeMillis();
        String s_iat = String.valueOf(currTime);
        String s_nbf = String.valueOf(currTime - TIME_OFFSET_MS);	//Pegging it to 300 sec before iat for possible sync issues
        standardClaims.put("nbf", s_nbf);
        standardClaims.put("iat", s_iat);
        System.out.println("ROBLOX CUSTOM TOKEN GENERATOR - end of overriding standard claims");
        log.info("Done adding 'nbf' and 'iat' to the standard claims");
        return standardClaims;
    }
    
    @Override
    public String buildBody(TokenValidationContext validationContext) throws APIManagementException {
    System.out.println("ROBLOX CUSTOM TOKEN GENERATOR - beginning of overriding buildBody() of AbstractJWTGenerator");
    log.info("Overriding buildBody() of AbstractJWTGenerator here - Handling the conversion of 'nbf' and 'iat' to long format.");
    String userAttributeSeparator = APIConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
    
        Map<String, String> standardClaims = populateStandardClaims(validationContext);
        Map<String, String> customClaims = populateCustomClaims(validationContext);

        //get tenantId
        int tenantId = APIUtil.getTenantId(validationContext.getValidationInfoDTO().getEndUserName());

        String claimSeparator = getMultiAttributeSeparator(tenantId);
        if (StringUtils.isNotBlank(claimSeparator)) {
            userAttributeSeparator = claimSeparator;
        }

        if (standardClaims != null) {
            if (customClaims != null) {
                standardClaims.putAll(customClaims);
            }

            JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();

            if(standardClaims != null) {
                Iterator<String> it = new TreeSet(standardClaims.keySet()).iterator();
                while (it.hasNext()) {
                    String claimURI = it.next();
                    String claimVal = standardClaims.get(claimURI);
                    List<String> claimList = new ArrayList<String>();
                    if (claimVal != null && claimVal.contains("{")) {
                        ObjectMapper mapper = new ObjectMapper();
                        try {
                            Map<String, String> map = mapper.readValue(claimVal, Map.class);
                            jwtClaimsSetBuilder.claim(claimURI, map);
                        } catch (IOException e) {
                            // Exception isn't thrown in order to generate jwt without claim, even if an error is
                            // occurred during the retrieving claims.
                            log.error("Error while reading claim values %s\n", e);
                        }
                    } else if (userAttributeSeparator != null && claimVal != null &&
                            claimVal.contains(userAttributeSeparator)) {
                        StringTokenizer st = new StringTokenizer(claimVal, userAttributeSeparator);
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
                            if (StringUtils.isNotBlank(attValue)) {
                                claimList.add(attValue);
                            }
                        }
                        jwtClaimsSetBuilder.claim(claimURI, claimList);
                    } else if ("exp".equals(claimURI)) {
                        jwtClaimsSetBuilder.expirationTime(new Date(Long.valueOf(standardClaims.get(claimURI))));
                    } else if ("iat".equals(claimURI)) {
                        jwtClaimsSetBuilder.issueTime(new Date(Long.valueOf(standardClaims.get(claimURI))));
                    } else if ("nbf".equals(claimURI)) {
                        jwtClaimsSetBuilder.notBeforeTime(new Date(Long.valueOf(standardClaims.get(claimURI))));
                    } else {
                        jwtClaimsSetBuilder.claim(claimURI, claimVal);
                    }
                }
            }
            System.out.println("ROBLOX CUSTOM TOKEN GENERATOR - end of overriding buildBody() of AbstractJWTGenerator");
            log.info("Done overriding buildBody() of AbstractJWTGenerator");
            
            return jwtClaimsSetBuilder.build().toJSONObject().toJSONString();
        }
        return null;
    }
    
}
