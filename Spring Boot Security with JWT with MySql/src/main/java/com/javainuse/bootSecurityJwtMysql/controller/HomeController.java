package com.javainuse.bootSecurityJwtMysql.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/*
    @AuthenticationPrincipal :
        @AuthenticationPrincipal will inject a principal if a user is authenticated,
        or null if no user is authenticated. This principal is the object coming from
        your UserDetailsService/AuthenticationManager!

        f you are not using the @AuthenticationPrincipal annotation, you would have to fetch
        the principal yourself, through the SecurityContextHolder.
        A technique often seen in legacy Spring Security applications.

    CSRF :
        you could inject the current session CSRFToken into each method :
            @GetMapping("/helloAdmin")
            public String helloAdmin(CsrfToken token){
                // method body
            }
 */
@RestController
public class HomeController {

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    @GetMapping("/hello")
    public String helloWorld(){
        return "hello world";
    }

    @PreAuthorize("hasRole('ADMIN')") // or @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/helloAdmin")
    public String helloAdmin(@AuthenticationPrincipal UserDetails userDetails){
        return "hello my love(admin)";
    }


}
    /*
        What are Authorities? What are Roles?

        An authority (in its simplest form) is just a string, it can be anything like:
        user, ADMIN, ROLE_ADMIN or 53cr37_r0l3.

        A role is an authority with a ROLE_ prefix. So a role called ADMIN is the same as
        an authority called ROLE_ADMIN.

        The distinction between roles and authorities is purely conceptual.

     */