package com.javainuse.bootSecurityJwtMysql.repository;

import com.javainuse.bootSecurityJwtMysql.model.Role;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface RoleRepository extends CrudRepository<Role, Long> {
//    Optional<Role> findByRoleName(String roleName);
}
