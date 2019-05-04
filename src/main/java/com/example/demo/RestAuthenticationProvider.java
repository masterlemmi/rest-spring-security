package com.example.demo;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.List;
import java.util.Set;


public class RestAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Autowired
    AuthenticationApi authenticationApi;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

    private volatile String userNotFoundEncodedPassword;
    //private UserDetailsService userDetailsService;


//    public RestAuthenticationProvider() {
//        setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
//    }

    @SuppressWarnings("deprecation")
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            logger.debug("Authentication failed: no credentials provided");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }

        String presentedPassword = authentication.getCredentials().toString();

        if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            logger.debug("Authentication failed: password does not match stored value");

            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials",
                    "Bad credentials"));
        }
    }

    protected final UserDetails retrieveUser(String name,
                                             UsernamePasswordAuthenticationToken auth)
            throws AuthenticationException {
        String password = auth.getCredentials().toString();
        UserDetails loadedUser = null;
        try {
            ResponseEntity<Principal> authenticationResponse =
                    authenticationApi.authenticate(name, password);

            if (authenticationResponse.getStatusCode().value() == 401) {
                return new User("wrongUsername", "wrongPass",
                        Lists.newArrayList());
            }
            Principal principalFromRest = authenticationResponse.getBody();
            Set<String> privilegesFromRest = Sets.newHashSet();

            //TODO: updaate this
            privilegesFromRest.add("ADMINSTRATIGN");

            // fill in the privilegesFromRest from the Principal
            String[] authoritiesAsArray =
                    privilegesFromRest.toArray(new String[privilegesFromRest.size()]);

            List<GrantedAuthority> authorities =
                    AuthorityUtils.createAuthorityList(authoritiesAsArray);

            loadedUser = new User(name, passwordEncoder.encode(password), true, true, true, true, authorities);
        } catch (Exception ex) {
            throw new AuthenticationServiceException(ex.getMessage());
        }
        return loadedUser;

    }

    @Override
    protected Authentication createSuccessAuthentication(Object principal,
                                                         Authentication authentication, UserDetails user) {
        int x = 0;
        int sum = x+ 1;
        System.out.println("SUCCESS");
        return super.createSuccessAuthentication(principal, authentication, user);
    }


}
