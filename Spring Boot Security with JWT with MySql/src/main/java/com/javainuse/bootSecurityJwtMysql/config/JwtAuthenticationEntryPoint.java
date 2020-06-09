package com.javainuse.bootSecurityJwtMysql.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;


/*
    AuthenticationEntryPoint is used to send an HTTP response that requests credentials from a client.
    Sometimes a client will proactively include credentials such as a username/password to request a resource.
    In these cases, Spring Security does not need to provide an HTTP response that requests credentials
    from the client since they are already included.
    In other cases, a client will make an unauthenticated request to a resource that they are
    not authorized to access. In this case, an implementation of AuthenticationEntryPoint is used to
    request credentials from the client. The AuthenticationEntryPoint implementation might perform
    a redirect to a log in page, respond with an WWW-Authenticate header, etc.

    this class will extend Spring's AuthenticationEntryPoint class and override its method commence.
    It rejects every unauthenticated request and send error code 401 instead of 403
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint, Serializable {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.error("Unauthorized error: {}", authException.getMessage());

        /*
            HttpServletResponse.SC_UNAUTHORIZED is the 401 Status code.
            It indicates that the request requires HTTP authentication.
         */
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorised");
    }
}
