/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.costlowcorp.microsoft;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.UUID;
import javax.enterprise.context.RequestScoped;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;

/**
 *
 * @author Erik
 */
@Path("/microsoft/oauth2init")
@RequestScoped
public class MicrosoftOAuthInit {

    private static final Logger LOG = System.getLogger(MicrosoftOAuthInit.class.getSimpleName());

    static {
        String clientId;
        String clientSecret;
        String authority;
        String redirect;
        Properties properties = new Properties();
        try (var in = Files.newInputStream(Paths.get(System.getProperty("user.home"), "quarkus-security.properties"))) {
            properties.load(in);
            clientId = properties.getProperty("microsoft.clientId");
            clientSecret = properties.getProperty("microsoft.clientSecret");
            authority = properties.getProperty("microsoft.authority");
            redirect=properties.getProperty("microsoft.redirect");
        } catch (IOException ex) {
            LOG.log(Level.ERROR, "Unable to read Microsoft OAuth properties.");
            clientId = "UNKNOWN";
            clientSecret = "UNKNOWN";
            authority = "UNKNOWN";
            redirect="UNKNOWN";
        }
        CLIENT_ID = clientId;
        CLIENT_SECRET = clientSecret;
        AUTHORITY = authority;
        REDIRECT_URI_SIGN_IN = redirect;
    }

    @Context
    SecurityContext sctx;

    static final String CLIENT_ID;
    static final String CLIENT_SECRET;

    static final String AUTHORITY;
    static final String REDIRECT_URI_SIGN_IN;

    @GET
    public Response check(@Context UriInfo uriInfo) throws UnsupportedEncodingException {
        LOG.log(Level.INFO, "Microsoft OAuth2 init");

        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();

        String url = getAuthorizationCodeUrl("", null, REDIRECT_URI_SIGN_IN, state, nonce);
        LOG.log(Level.INFO, url);
        try {
            var location = new URI(url);
            return Response.seeOther(location).build();
        } catch (URISyntaxException ex) {
            LOG.log(Level.ERROR, "Unable to construct redirect URI", ex);
        }

        throw new InternalServerErrorException("Unable to perform redirect");
    }

    String getAuthorizationCodeUrl(String claims, String scope, String registeredRedirectURL, String state, String nonce)
            throws UnsupportedEncodingException {

        String urlEncodedScopes = scope == null
                ? URLEncoder.encode("openid offline_access profile Mail.Read email User.Read", "UTF-8")
                : URLEncoder.encode("openid offline_access profile" + " " + scope, "UTF-8");
        LOG.log(Level.INFO, "scope request is {}", urlEncodedScopes);
        String authorizationCodeUrl = AUTHORITY + "oauth2/v2.0/authorize?"
                + "response_type=code&"
                + "response_mode=form_post&"
                + "redirect_uri=" + URLEncoder.encode(registeredRedirectURL, "UTF-8")
                + "&client_id=" + CLIENT_ID
                + "&scope=" + urlEncodedScopes
                + (claims == null || claims.isEmpty() ? "" : "&claims=" + claims)
                + "&prompt=consent"
                + "&state=" + state
                + "&nonce=" + nonce;

        return authorizationCodeUrl;
    }
}
