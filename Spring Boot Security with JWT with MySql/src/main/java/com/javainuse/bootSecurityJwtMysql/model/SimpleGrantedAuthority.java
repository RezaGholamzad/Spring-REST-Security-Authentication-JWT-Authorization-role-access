package com.javainuse.bootSecurityJwtMysql.model;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

/*
    Of course, Spring Security doesn’t let you get away with just using Strings.
    There’s a Java class representing your authority String,
    a popular one being SimpleGrantedAuthority.
 */
@Data
public class SimpleGrantedAuthority implements GrantedAuthority {

    private final String role;

    @Override
    public String getAuthority() {
        return this.role;
    }
}
