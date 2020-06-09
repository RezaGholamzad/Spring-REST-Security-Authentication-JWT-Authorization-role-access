package com.javainuse.bootSecurityJwtMysql.config;

import com.javainuse.bootSecurityJwtMysql.service.JwtUserDetailsService;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
    OncePerRequestFilter :
        OncePerRequestFilter, which implements the interface Filter and adds some features.
        This is so that the filter is only executed once by request.

        The JwtRequestFilter extends the Spring Web Filter OncePerRequestFilter class.
        For any incoming request this Filter class gets executed.
        It checks if the request has a valid JWT token.
        If it has a valid JWT Token then it sets the Authentication in the context,
        to specify that the current user is authenticated.

    SecurityContext and SecurityContextHolder :
        The SecurityContext and SecurityContextHolder are two fundamental classes of Spring Security.
        The SecurityContext is used to store the details of the currently authenticated user,
        also known as a principle. So, if you have to get the username or any other user details,
        you need to get this SecurityContext first. The SecurityContextHolder is a helper class,
        which provide access to the security context. By default, it uses a ThreadLocal object
        to store security context, which means that the security context is always available
        to methods in the same thread of execution, even if you don’t pass the SecurityContext object around.
        Don’t worry about the ThreadLocal memory leak in web application though, Spring Security
        takes care of cleaning ThreadLocal.

        The SecurityContext contains an Authentication object.
        Authentication contains:
        1) principal - identifies the user.
        When authenticating with a username/password this is often an instance of UserDetails.
        2) credentials - Often a password. In many cases this will be cleared
        after the user is authenticated to ensure it is not leaked.
        3)authorities - the GrantedAuthority are high level permissions the user is granted.
        A few examples are roles or scopes.

        The storage part i.e. SecurityContext is stored in ThreadLocal is optional,
        but it’s also good to know the detail. Just remember, if you ever need user details e.g.
        username etc, you better ask for Principal or Authentication object in Spring MVC controller,
        rather than using SecurityContextHolder to obtain them.


 */

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private final JwtUserDetailsService jwtUserDetailsService;

    private final JwtTokenUtil jwtTokenUtil;

    public JwtRequestFilter(JwtUserDetailsService jwtUserDetailsService, JwtTokenUtil jwtTokenUtil) {
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    /*
      Same contract as for doFilter(This is where your filter processing occurs. Each time a
        target resource (such as a servlet or JSP page) is requested, where the target resource
        is mapped to a chain of one or more filters, the servlet container calls the doFilter()
        method of each filter in the chain)
  ,     but guaranteed to be just invoked once per request within a single request thread.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader("Authorization");

        String jwtToken = null;
        String username = null;

        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")){
            jwtToken = requestTokenHeader.substring(7);

            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            }
            /*
                @throws IllegalArgumentException if the {@code claimsJwt} string is {@code null}
                or empty or only whitespace in parseClaimsJwt(token) method in JwtTokenUtil class
             */
            catch (IllegalArgumentException e){
                System.out.println("Unable to get JWT Token");
            }
            /*
                @throws ExpiredJwtException  if the specified JWT is a Claims JWT and
                the Claims has an expiration time
                before the time this method is invoked, in parseClaimsJwt(token) method in JwtTokenUtil class
             */
            catch (ExpiredJwtException e){
                System.out.println("JWT Token has expired");
            }

        }else {
            // logger of type LogFactory
            logger.warn("JWT Token does not begin with Bearer String");
        }

        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

            // if token is valid configure Spring Security to manually set authentication
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)){

                /*
                    UsernamePasswordAuthenticationToken:
                        An Authentication implementation that is designed for simple presentation of a
                        username and password.

                    principle = userDetails
                    credentials = null
                    authorities = userDetails.getAuthorities()
                 */
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null,
                                userDetails.getAuthorities());
                /*
                    WebAuthenticationDetailsSource:
                        Implementation of AuthenticationDetailsSource which builds the details object from
                        an HttpServletRequest object, creating a WebAuthenticationDetails.
                        buildDetails method called by a class when it wishes a new authentication details
                        instance to be created.

                        It seems this line is to load the Session info for current request for the server side.
                        However, as we all know, this project relies on token based authentication,
                        and hence loading the session in the server is no use any more
                        (I guess loading the session here is essential if we use
                        the traditional session_id authentication).
                 */
//                usernamePasswordAuthenticationToken
//                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //set the current UserDetails in SecurityContext
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
                /*
                    After this, every time you want to get UserDetails, just use SecurityContext:

                    UserDetails userDetails =
	                (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

                     userDetails.getUsername()
                     userDetails.getPassword()
                     userDetails.getAuthorities()
                 */
            }
        }

        /*
             FilterChain will be used to continue the flow of the request.
                call next filter in the filter chain or the target resource
                (such as a servlet or JSP page) if this method is called
                from the last filter in the chain.
                This results in the target servlet being invoked by its service() method.
         */
        filterChain.doFilter(request,response);

    }
}
