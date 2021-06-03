package com.example.demo.config.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.annotation.PostConstruct;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MyUserDetailsService implements UserDetailsService {
    private Map<String, User> roles = new HashMap<>();

    @PostConstruct
    public void init(){
        roles.put("admin", new User("admin", "{noop}admin", getAuthority("ROLE_ADMIN")));
        roles.put("user", new User("user", "{noop}user", getAuthority("ROLE_USER")));
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return roles.get(s);
    }

    private List<GrantedAuthority> getAuthority(String role){
        return Collections.singletonList(new SimpleGrantedAuthority(role));
    }
}
