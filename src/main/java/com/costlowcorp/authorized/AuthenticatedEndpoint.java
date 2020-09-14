package com.costlowcorp.authorized;

import java.lang.System.Logger.Level;
import javax.enterprise.context.RequestScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;


@Path("/app/me")
@RequestScoped
public class AuthenticatedEndpoint {
    
    @Context
    SecurityContext sctx;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        System.getLogger(AuthenticatedEndpoint.class.getSimpleName()).log(Level.INFO, "Showing logged in user");
        return sctx.getUserPrincipal().getName();
        
    }
}