package com.springsecurity.jdbc.services;

import com.springsecurity.jdbc.models.AuthenticationRequest;
import com.springsecurity.jdbc.models.User;
import com.springsecurity.jdbc.repositories.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.Collection;

@Service
public class UserService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User userInfo = userRepository.getUserInfo(username);
            logger.info("userInfo= " + userInfo);
            if (userInfo != null) {
//              Adding user roles to granted authorities collection
                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(userInfo.getRole()));

                return (UserDetails) new org.springframework.security.core.userdetails.User(
                        userInfo.getUserName(), userInfo.getPassword(), authorities);
            } else {
                throw new UsernameNotFoundException("User not found with username: " + username);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    public int save(AuthenticationRequest user) {
        User newUser = new User();
        newUser.setUserName(user.getUsername());
//        System.out.println(bcryptEncoder.encode(user.getPassword()));
//        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setPassword(user.getPassword());
        return userRepository.signUp(newUser);
    }
}