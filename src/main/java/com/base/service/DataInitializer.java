package com.base.service;


import com.base.entity.Authority;
import com.base.entity.Role;
import com.base.entity.User;
import com.base.repository.AuthorityRepository;
import com.base.repository.RoleRepository;
import com.base.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * @author YISivlay
 */
@Component
public class DataInitializer {

    private final AuthorityRepository authorityRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public DataInitializer(AuthorityRepository authorityRepository,
                           RoleRepository roleRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.authorityRepository = authorityRepository;
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void init() {
        // ---------------------------
        // Authorities
        // ---------------------------
        Authority read = authorityRepository.findByName("READ_PRIVILEGE")
                .orElseGet(() -> authorityRepository.save(new Authority("READ_PRIVILEGE")));

        Authority write = authorityRepository.findByName("WRITE_PRIVILEGE")
                .orElseGet(() -> authorityRepository.save(new Authority("WRITE_PRIVILEGE")));

        Authority delete = authorityRepository.findByName("DELETE_PRIVILEGE")
                .orElseGet(() -> authorityRepository.save(new Authority("DELETE_PRIVILEGE")));

        // ---------------------------
        // Roles
        // ---------------------------
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(new Role("ROLE_USER", Set.of(read))));

        Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(new Role("ROLE_ADMIN", Set.of(read, write, delete))));

        // ---------------------------
        // Default Admin User
        // ---------------------------
        userRepository.findByUsername("admin").orElseGet(() -> {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("password")); // BCrypt
            admin.setEnabled(true);
            admin.setRoles(Set.of(adminRole));
            return userRepository.save(admin);
        });

        userRepository.findByUsername("user").orElseGet(() -> {
            User user = new User();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("password")); // BCrypt
            user.setEnabled(true);
            user.setRoles(Set.of(userRole));
            return userRepository.save(user);
        });
    }

}
