package com.javainuse.bootSecurityJwtMysql.config;

import com.javainuse.bootSecurityJwtMysql.service.JwtUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


/*
        the AuthenticationManager :

            the authentication manager assumes the job of establishing a user's identity.
            An authentication manager is defined by the
            org.springframework.security.authentication.AuthenticationManager interface.
            The authenticate method will attempt to authenticate the user using
            the org.springframework.security.core.Authentication object
            (which carries the principal and credentials). If successful,
            the authenticate method returns a complete Authentication object,
            including information about the user's granted authorities.
            If authentication fails, an authentication exception will be thrown.

            When you call authenticate(new UsernamePasswordAuthenticationToken(username, password))
            in JwtAuthenticationController, it is passing the UsernamePasswordAuthenticationToken
            to the default AuthenticationProvider, which will use the userDetailsService
            to get the user based on username and compare that user's password
            with the one in the authentication token.

            We can set up global or local AuthenticationManager if we extend WebSecurityConfigurerAdapter.
            For a local AuthenticationManager, we could override configure(AuthenticationManagerBuilder).
            For a global AuthenticationManager, we should define an AuthenticationManager as a bean.

        the ProviderManager :
            The AuthenticationManager interface is quite simple and you could easily
            implement your own AuthenticationManager. But Spring Security comes with
            org.springframework.security.authentication.ProviderManager,
            an implementation of AuthenticationManager that is suitable for most situations.
            ProviderManager is the default implementation of AuthenticationManager.
            It delegates the authentication process to a list of AuthenticationProvider instances.

            The purpose of ProviderManager is to enable you to authenticate users against
            multiple identity management sources. Rather than relying on itself to perform authentication,
            ProviderManager steps one by one through a collection of authentication providers,
            until one of them successfully authenticates the user (or until it runs out of providers).
            This makes it possible for Spring Security to support multiple mechanisms for a single request.

            ProviderManager is given a list of authentication providers through its providers property.
            Typically, you'll only need one authentication provider, but in some cases,
            it may be useful to supply a list of several providers so that if authentication fails against
            one provider, another provider will be tried.

        the AuthenticationProvider :
            Spring Security comes with authentication providers for many occasions.
            Most common are the DaoAuthenticationProvider for retrieving user information
            from a database. LdapAuthenticationProvider for authentication against a
            Lightweight Directory Access Protocol (LDAP) server.
            JaasAuthenticationProvider for retrieving user information from a JAAS login configuration.

        the DaoAuthenticationProvider :
            is a simple authentication provider that uses a Data Access Object (DAO) to retrieve
            user information from a relational database.
            It leverages a UserDetailsService (as a DAO) in order to lookup the username, password
            and GrantedAuthority. It authenticates the user simply by comparing the password submitted
            in a UsernamePasswordAuthenticationToken against the one loaded by the UserDetailsService.

*/
/*
    @EnableWebSecurity:
    Add this annotation to an @Configuration class
        to enable Spring Security’s web security support and provide the Spring MVC integration.
        It also extends WebSecurityConfigurerAdapter and overrides a couple of
        its methods to set some specifics of the web security configuration.

    configure(HttpSecurity http): Configures HttpSecurity ,
        for example, authorizing requests and role access.

    configure(WebSecurity web): Configures WebSecurity,
       for example, we can ignore certain requests (eg. loading JS file) to be authenticated.

    configure(AuthenticationManagerBuilder auth): Configures AuthenticationManager.

    authenticationManagerBean(): Exposes AuthenticationManager as bean.

    userDetailsServiceBean(): Exposes UserDetailsService as bean.

    @EnableGlobalMethodSecurity(prePostEnabled = true):
        To use @PreAuthorize and @PostAuthorize annotations in our Spring Security application,
        we need to enable pre-post annotations.

        securedEnabled = true :
        The securedEnabled property enables support for the @Secured annotation.

        jsr250Enabled = true :
        The jsr250Enabled property enables support for the @RolesAllowed annotation.

        @PreAuthorize/@PostAuthorize are also (newer) Spring specific annotations and more powerful
        than the @Secured and @RolesAllowed, as they can contain not only authorities/roles,
        but also any valid SpEL expression.

*/
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true
//        ,securedEnabled = true
//        ,jsr250Enabled = true
        )
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtRequestFilter jwtRequestFilter;

    private final JwtUserDetailsService jwtUserDetailsService;

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    /*
        @Lazy :
        By default, when an application context is being refreshed,
            every bean in the context is created and its dependencies are injected.
        By contrast, when a bean definition is configured to be initialized lazily
            it will not be created and its dependencies will not be injected until it’s needed.
        enabling lazy initialization can reduce startup times quite dramatically.
        In a web application lazy initialization can lead to increased latency for
            HTTP requests that trigger bean initialization.
            This will typically just be the first request but it may have an adverse effect
            on load-balancing and auto-scaling.

        The reason for putting the @Lazy here:
            The dependencies of some of the beans in the application context form a cycle:

              webSecurityConfig ----@Bean----> passwordEncoder
                 ↑                                    |
             @Autowired                           @Autowired
                 |                                    |
                 |                                    |
             jwtUserDetailsService <------------------|
     */

    public WebSecurityConfig(@Lazy JwtRequestFilter jwtRequestFilter, @Lazy JwtUserDetailsService jwtUserDetailsService, JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint) {
        this.jwtRequestFilter = jwtRequestFilter;
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /*
        In this case Spring Security needs you to define two beans to get authentication up and running.

        1) UserDetailsService.

        2)A PasswordEncoder.

        AuthenticationManagerBuilder :
        is a helper class that eases the set up of UserDetailService,
        AuthenticationProvider, and other dependencies to build an AuthenticationManager.

        configure AuthenticationManager so that it knows from where to load
        user for matching credentials,
        Use BCryptPasswordEncoder

     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(jwtUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    /*
        By overriding the adapter’s configure(HttpSecurity) method, you get a nice little DSL with
        which you can configure your FilterChain.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
            if you are using cookies (or other authentication methods that the browser can do automatically)
            then you need CSRF protection. If you aren't using cookies then you don't.
         */
        http.csrf().disable()

                // do not authenticate this particular request
                .authorizeRequests()
                .antMatchers("/authenticate", "/register")
                .permitAll()

                // all other requests need to be authenticate
                .anyRequest()
                .authenticated()
                .and()

                // make sure we use stateless session, session won`t be used to store user`s state
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                /*
                    Statelessness(token-based) means that every HTTP request happens in complete isolation.
                        When the client makes an HTTP request, it includes all the information
                        necessary for the server to fulfill that request.
                        The server never relies on information from previous requests.
                        If that information was important, the client would have to send
                        it again in subsequent request. Statelessness also brings new features.
                        It’s easier to distribute a stateless application across load-balanced servers.
                        A stateless application is also easy to cache.
                     In the session-based approach, a session id—which is a kind of server generated
                        token—is generated and stored in a cookie within the JSESSIONID parameter.
                        This means that the server stores the session key in itself so when
                        the server reboots or requests are redirected to another server by load balancer,
                        your "state" of session key becomes useless.
                */

                .and()
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)

                // Allows adding a Filter before one of the known Filter classes.
                .and()
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

                /*
                    read Servlet Security in spring security document(excellent!!!)
                    for understand filter mechanism.

                    So, when an HTTPRequest comes in, it will go through all these filters,
                    before your request finally hits your @RestControllers. The order is important,
                    too, starting at the top of that list and going down to the bottom.

                    here’s the explanations for a few of those filters
                    in order:

	                UsernamePasswordAuthenticationFilter :
	                    When the user submits their username and password,
	                    the UsernamePasswordAuthenticationFilter creates a
	                    UsernamePasswordAuthenticationToken which is a type of Authentication by
	                    extracting the username and password from the HttpServletRequest.

	                    Tries to find a username/password request parameter/POST body and if found,
	                    tries to authenticate the user with those values.

                    DefaultLoginPageGeneratingFilter: Generates a login page for you,
                        if you don’t explicitly disable that feature. THIS filter is why you get a default
                        login page when enabling Spring Security.

                    DefaultLogoutPageGeneratingFilter: Generates a logout page for you, if you don’t
                    explicitly disable that feature.

	                BasicAuthenticationFilter: Tries to find a Basic Auth HTTP Header on the request and if
	                    found, tries to authenticate the user with the header’s username and password.

                    FilterSecurityInterceptor: Does your authorization.
                */

    }
}
