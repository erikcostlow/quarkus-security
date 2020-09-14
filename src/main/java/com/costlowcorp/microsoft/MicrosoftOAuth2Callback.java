/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.costlowcorp.microsoft;

import com.costlowcorp.quarkus.TokenUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.graph.logger.DefaultLogger;
import com.microsoft.graph.logger.ILogger;
import com.microsoft.graph.logger.LoggerLevel;
import com.microsoft.graph.models.extensions.IGraphServiceClient;
import com.microsoft.graph.models.extensions.User;
import com.microsoft.graph.requests.extensions.GraphServiceClient;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

/**
 *
 * @author Erik
 */
@Path("/rest/microsoft/oauth2callback")
public class MicrosoftOAuth2Callback {

    private static final Logger LOG = System.getLogger(MicrosoftOAuth2Callback.class.getSimpleName());

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @GET
    public Response check(@Context UriInfo uriInfo) {
        LOG.log(Level.INFO, "OAuth2callback");
        return Response.ok("got").build();
    }

    @POST
    @Produces(value = MediaType.APPLICATION_JSON)
    public Response post(@Context UriInfo uriInfo,
            @FormParam("state") String state,
            @FormParam("error") String error,
            @FormParam("error_description") String errorDescription,
            @FormParam("code") String code,
            @FormParam("session_state") String sessionState,
            MultivaluedMap<String, String> formParams) {
        //LOG.log(Level.INFO, "OAuth2callback for state {}", state);
        if (error != null) {
            LOG.log(Level.INFO, "Error authenticating {} - {}", error, errorDescription);
            return Response.status(Response.Status.FORBIDDEN).entity(error).build();
        }

        if (code != null) {
            LOG.log(Level.INFO, "Successfully accessed");
            LOG.log(Level.INFO, "Check the state UUID against previous");
            String token = getTokenResponse(code);
            LOG.log(Level.INFO, "access token: {}", token);
            try {
                Map<String, String> map = MAPPER.readValue(token, Map.class);
                var refreshToken = map.get("refresh_token");

                LOG.log(Level.INFO, "Parsing JWT using mime");

                String jwtDecoded = new String(Base64.getMimeDecoder().decode(map.get("access_token")));
                LOG.log(Level.INFO, "Decoded JWT is {}", jwtDecoded);
                System.out.println(jwtDecoded);

                map.put("access_token", "REDACTED " + map.get("access_token").substring(0, 10)); //JWT
                map.put("refresh_token", "REDACTED " + map.get("refresh_token").substring(0, 10));
                map.put("id_token", "REDACTED " + map.get("id_token").substring(0, 10)); //JWT

                var authenticationProvider = new CostlowAuthenticationAdapter(refreshToken);
                ILogger logger = new DefaultLogger();
                logger.setLoggingLevel(LoggerLevel.ERROR);
                IGraphServiceClient graphClient
                        = GraphServiceClient
                                .builder()
                                .authenticationProvider(authenticationProvider)
                                .logger(logger)
                                .buildClient();

                User user = graphClient
                        .me()
                        .buildRequest()
                        .get();
                map.put("displayName", user.displayName);

                var spaceIndex = user.displayName.indexOf(' ');
                var email = spaceIndex == -1 ? user.displayName : user.displayName.substring(0, spaceIndex - 1);
                var jwt = makeToken(email);
                map.put("jwt", jwt);

                return Response.ok(
                        MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(map)
                ).build();
            } catch (JsonProcessingException ex) {
                LOG.log(Level.WARNING, "Unable to read response", ex);
            } catch (IOException ex) {
                LOG.log(Level.WARNING, "Unable to map response", ex);
            } catch (Exception ex) {
                LOG.log(Level.WARNING, "Unable to crate token", ex);
            }
        }

        return Response.ok("Done").build();
    }

    private String getTokenResponse(String code) {
        var post = RequestBuilder.post(MicrosoftOAuthInit.AUTHORITY + "oauth2/v2.0/token")
                .addParameter("client_id", MicrosoftOAuthInit.CLIENT_ID)
                .addParameter("scope", "openid offline_access profile Mail.Read email User.Read")
                .addParameter("redirect_uri", MicrosoftOAuthInit.REDIRECT_URI_SIGN_IN)
                .addParameter("code", code)
                .addParameter("grant_type", "authorization_code")
                .addParameter("client_secret", MicrosoftOAuthInit.CLIENT_SECRET)
                .build();
        final CloseableHttpClient httpclient = HttpClients.createDefault();
        try (var c = httpclient.execute(post);
                InputStream in = c.getEntity().getContent()) {
            var status = c.getStatusLine().getStatusCode();
            LOG.log(Level.INFO, "Status {}", status);
            String val = IOUtils.toString(in, "UTF-8");
            if (status != 200) {
                LOG.log(Level.INFO, "Unable to receive token, status {} with error {}", status, val);
                return null;
            }
            return val;
        } catch (IOException ex) {
            LOG.log(Level.INFO, "Error sending/receiving request", ex);
        }

        return "unknown";
    }

    public static String makeToken(String username) throws Exception {
        Map<String, Object> tokenMap = Map.of(
                "iss", "https://quarkus.io/using-jwt-rbac",
                "upn", username,
                "preferred_username", username,
                "jti", UUID.randomUUID().toString(),
                "sub", "jdoe-using-jwt-rbac",
                "aud", "using-jwt-rbac",
                "roleMappings", Map.of("group1", "Group1MappedRole"),
                "groups", List.of("Echoer", "Tester", "Subscriber")
        );
        String jsonToken = TokenUtils.generateTokenString(tokenMap, Collections.EMPTY_MAP);
        return jsonToken;
    }
}
