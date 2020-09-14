/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.costlowcorp.microsoft;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.graph.authentication.IAuthenticationProvider;
import com.microsoft.graph.core.ClientException;
import com.microsoft.graph.http.IHttpRequest;
import com.microsoft.graph.options.HeaderOption;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Map;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

/**
 *
 * @author Erik
 */
public class CostlowAuthenticationAdapter implements IAuthenticationProvider {

    private static final Logger LOG = System.getLogger(CostlowAuthenticationAdapter.class.getSimpleName());
    
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CloseableHttpClient httpclient = HttpClients.createDefault();

    /**
     * The authorization header name.
     */
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

    /**
     * The bearer prefix.
     */
    public static final String OAUTH_BEARER_PREFIX = "bearer ";
    
    private final String refreshToken;
    
    public CostlowAuthenticationAdapter(String refreshToken){
        this.refreshToken = refreshToken;
    }

    @Override
    public void authenticateRequest(IHttpRequest request) {

        for (final HeaderOption option : request.getHeaders()) {
            if (option.getName().equals(AUTHORIZATION_HEADER_NAME)) {
                LOG.log(Level.DEBUG, "Found an existing authorization header!");
                return;
            }
        }

        try {
            final String accessToken = getAccessToken();
            request.addHeader(AUTHORIZATION_HEADER_NAME, OAUTH_BEARER_PREFIX + accessToken);
        } catch (ClientException e) {
            final String message = "Unable to authenticate request, No active account found";
            final ClientException exception = new ClientException(message,
                    e);
            LOG.log(Level.ERROR, message, exception);
            throw exception;
        }
    }

    private String getAccessToken() {
        var post = RequestBuilder.post(MicrosoftOAuthInit.AUTHORITY + "oauth2/v2.0/token")
                .addParameter("client_id", MicrosoftOAuthInit.CLIENT_ID)
                .addParameter("scope", "email Mail.Read openid profile User.Read")
                .addParameter("refresh_token", refreshToken)
                .addParameter("grant_type", "refresh_token")
                .addParameter("client_secret", MicrosoftOAuthInit.CLIENT_SECRET)
                .build();
        try (var c = httpclient.execute(post);
                InputStream in = c.getEntity().getContent()) {
            LOG.log(Level.INFO, "Status {}", c.getStatusLine().getStatusCode());
            String val = IOUtils.toString(in, "UTF-8");
            //LOG.info("Value is {}", val);
            Map<String, String> map = MAPPER.readValue(val, Map.class);
            
            var retval = map.get("access_token");
            LOG.log(Level.INFO, "access token is {}", retval);
            return retval;
        } catch (IOException ex) {
            LOG.log(Level.INFO, "Error sending/receiving request", ex);
        }

        return "unknown";
    }
}
