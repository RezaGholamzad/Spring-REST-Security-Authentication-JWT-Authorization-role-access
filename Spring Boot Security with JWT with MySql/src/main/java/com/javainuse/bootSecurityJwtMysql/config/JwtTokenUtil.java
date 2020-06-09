package com.javainuse.bootSecurityJwtMysql.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

//The JwtTokenUtil is responsible for performing JWT operations like creation and validation
@Component
public class JwtTokenUtil implements Serializable {

    /*
        The serialization at runtime associates with each serializable class a version number,
        called a serialVersionUID, which is used during deserialization to verify that the sender
        and receiver of a serialized object have loaded classes for that object that are compatible
        with respect to serialization.

        SerialVersionUID is used to ensure that during deserialization the same class
        (that was used during serialize process) is loaded.
     */
    private static final long serialVersionUID = -2550185165626007488L;

    private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60 ;

    @Value("${jwt.secret}")
    private String secret;

    //for retrieve any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token){
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsTFunction){
        final Claims claims = getAllClaimsFromToken(token);
        return claimsTFunction.apply(claims);
    }

    //retrieve username from jwt token
    public String getUsernameFromToken(String token){
        return getClaimFromToken(token, Claims::getSubject);
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token){
        return getClaimFromToken(token, Claims::getExpiration);
    }

    //check if the token has expired
    private Boolean isTokenExpired(String token){
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /*
        creating the token :
            1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
            2. Sign the JWT using the HS512 algorithm and secret key.
            3. According to JWS Compact Serialization
            (https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
            compaction of the JWT to a URL-safe string
     */
    private String doGenerateToken(Map<String, Object> claims, String subject){
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    public String generateToken(UserDetails userDetails){
        Map<String,Object> claims = new HashMap<>();
        return doGenerateToken(claims, userDetails.getUsername());
    }

    //validate token
    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = getUsernameFromToken(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

}
