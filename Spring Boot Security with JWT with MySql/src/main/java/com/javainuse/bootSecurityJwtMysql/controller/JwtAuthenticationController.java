package com.javainuse.bootSecurityJwtMysql.controller;

import com.javainuse.bootSecurityJwtMysql.config.JwtTokenUtil;
import com.javainuse.bootSecurityJwtMysql.model.JwtRequest;
import com.javainuse.bootSecurityJwtMysql.model.JwtResponse;
import com.javainuse.bootSecurityJwtMysql.model.UserDTO;
import com.javainuse.bootSecurityJwtMysql.repository.UserRepository;
import com.javainuse.bootSecurityJwtMysql.service.JwtUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

/*
    @CrossOrigin:
        The following defaults are applied if not already set:
        Allow all origins.
        Allow "simple" methods GET, HEAD and POST.
        Allow all headers.
        Set max age to 1800 seconds (30 minutes).
 */

@RestController
@CrossOrigin
public class JwtAuthenticationController {

    private final AuthenticationManager authenticationManager;

    private final JwtUserDetailsService jwtUserDetailsService;

    private final JwtTokenUtil jwtTokenUtil;

    private final UserRepository userRepository;

    public JwtAuthenticationController(AuthenticationManager authenticationManager,
                                       JwtUserDetailsService jwtUserDetailsService,
                                       JwtTokenUtil jwtTokenUtil,
                                       UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUserDetailsService = jwtUserDetailsService;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@Valid @RequestBody JwtRequest jwtRequest) throws Exception {
        authenticate(jwtRequest.getUsername(), jwtRequest.getPassword());

        UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(jwtRequest.getUsername());

        final String token = jwtTokenUtil.generateToken(userDetails);

        return ResponseEntity.ok(new JwtResponse(token));
    }

    public void authenticate(String username, String password) throws Exception {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(username, password));

            // UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            // userDetails.getUsername()
            // userDetails.getPassword()
            // userDetails.getAuthorities()
            /*
                If we want to get more data (id, email…), we can create an implementation of
                this UserDetails interface.
             */
        }
//        DisabledException must be thrown if an account is disabled
        catch (DisabledException e){
            throw new Exception("USER_DISABLED", e);
        }
//        BadCredentialsException must be thrown if incorrect credentials are presented
        catch (BadCredentialsException e){
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@Valid @RequestBody UserDTO userDTO){
        if (userRepository.existsByUsername(userDTO.getUsername())){
            return ResponseEntity.badRequest()
                    .body(new Exception("Error: Username is already taken!"));
        }
        return ResponseEntity.ok(jwtUserDetailsService.save(userDTO));
    }


}
    /*
        implementation of this UserDetails interface :

        @Data
        public class UserDetailsImpl implements UserDetails {
	        private static final long serialVersionUID = 1L;

	        private Long id;

	        private String username;

	        private String email;

	        @JsonIgnore
	        private String password;

	        private Collection<? extends GrantedAuthority> authorities;

	        public UserDetailsImpl(Long id, String username, String email, String password,
	        		Collection<? extends GrantedAuthority> authorities) {
	        	this.id = id;
	        	this.username = username;
	        	this.email = email;
	        	this.password = password;
	        	this.authorities = authorities;
	        }

	        public static UserDetailsImpl build(User user) {
	        	List<GrantedAuthority> authorities = user.getRoles().stream()
	        			.map(role -> new SimpleGrantedAuthority(role.getName().name()))
	        			.collect(Collectors.toList());

	        	return new UserDetailsImpl(
	        			user.getId(),
	        			user.getUsername(),
	        			user.getEmail(),
	        			user.getPassword(),
	        			authorities);
	        }

	        @Override
	        public Collection<? extends GrantedAuthority> getAuthorities() {
	        	return authorities;
	        }

	    }

	    change in JwtUserDetailsService:

            @Override
            @Transactional
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                User user = userRepository.findByUsername(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

                return UserDetailsImpl.build(user);
            }

}
     */

