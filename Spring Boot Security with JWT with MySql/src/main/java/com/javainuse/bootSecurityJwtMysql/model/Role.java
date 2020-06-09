package com.javainuse.bootSecurityJwtMysql.model;

import lombok.Data;

import javax.persistence.*;
import java.util.Collection;

/*
    initialize role table:
        INSERT INTO test.role (id, role_name) VALUES (100, 'ROLE_ADMIN');
        INSERT INTO test.role (id, role_name) VALUES (200, 'ROLE_USER');
 */
@Data
@Entity
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /*
        if we use of @ManyToMany in here a two-sided relationship is created.
        This means that when the user recovers from the database, the user roles are returned.
        These roles refer to users who have these roles, which should not be the case.
        So the relationship has to be one-sided
     */
//    @ManyToMany(mappedBy = "roles")
//    private Collection<User> users;

    private String roleName;
}
