package com.javainuse.bootSecurityJwtMysql.service;

import com.javainuse.bootSecurityJwtMysql.model.Role;
import com.javainuse.bootSecurityJwtMysql.model.SimpleGrantedAuthority;
import com.javainuse.bootSecurityJwtMysql.model.User;
import com.javainuse.bootSecurityJwtMysql.model.UserDTO;
import com.javainuse.bootSecurityJwtMysql.repository.RoleRepository;
import com.javainuse.bootSecurityJwtMysql.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/*
    UserDetailsService interface:
        The UserDetailsService is a core interface in Spring Security framework,
        which is used to retrieve the user’s authentication and authorization information.
        It has a single read-only method named as loadUserByUsername()
        which locate the user based on the username.

        The result of the search, if existing, then validates the credentials given through
        the login form with the user information retrieved through the UserDetailsService.
        Spring Security will pick the UserDetailsService implementation you provided,
        and this will be used to authenticate.

    PasswordEncoder interface:
        Service interface for encoding passwords.
        The preferred implementation is BCryptPasswordEncoder.
        This interface defines the method encode() to convert the plain password
        into the encoded form and the method matches() to compare a plain password
        with the encoded password.
*/
@Service
public class JwtUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder bCryptEncoder;

    public JwtUserDetailsService(UserRepository repository, RoleRepository roleRepository, PasswordEncoder bCryptEncoder) {
        this.userRepository = repository;
        this.roleRepository = roleRepository;
        this.bCryptEncoder = bCryptEncoder;
    }

    @Transactional
    /*
        @Transactional :
            This will then start a db transaction for the duration of the authenticate method
            allowing any lazy collection to be retrieved from the db as and when you try to use them.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("user not found with username : " + username));

        List<SimpleGrantedAuthority> grantedAuthorities = user.getRoles()
                .parallelStream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(), user.getPass(), grantedAuthorities);
        /*
            org.springframework.security.core.userdetail.User, which is a sensible, default UserDetails
            implementation that you could use. That would mean potentially mapping/copying between your
            entities/database tables and this user class. Alternatively, you could simply make your entities
            implement the UserDetails interface.

            explanation new ArrayList<>():
                You can grant different GrantedAuthorities (permissions) to users by putting them into
                the security context. You normally do that by implementing your own UserDetailsService
                that returns a UserDetails implementation that returns the needed GrantedAuthorities.
                Roles are just "permissions" with a naming convention that says that a role
                is a GrantedAuthority that starts with the prefix ROLE_.There's nothing more.
                So hasAuthority('ROLE_ADMIN') means the the same as hasRole('ADMIN')
                because the ROLE_ prefix gets added automatically.
         */
    }



    public User save(UserDTO userDTO){

        User newUser = new User();
        newUser.setUsername(userDTO.getUsername());
        newUser.setPass(bCryptEncoder.encode(userDTO.getPassword()));

        // roles
        List<Long> roleId = new ArrayList<>();
        roleId.add(0,100L); // admin
        roleId.add(1,200L); // user

        //set roles to user
        List<Role> roles = new ArrayList<>();
        if (newUser.getUsername().equals("admin")){
            roles = (List<Role>) roleRepository.findAllById(roleId);
        }else {
            roles.add(roleRepository.findById(200L).get());
        }
        newUser.setRoles(roles);
        return userRepository.save(newUser);
    }
}
