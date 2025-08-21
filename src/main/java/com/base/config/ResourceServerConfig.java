package com.base.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author YISivlay
 */
@Configuration
public class ResourceServerConfig {

    private static final int RESOURCE_SERVER_ORDER = 2;

    @Bean
    @Order(RESOURCE_SERVER_ORDER)
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        var converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName("authorities");
        converter.setAuthorityPrefix("ROLE_"); // Keep standard Spring Security prefix

        var jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(converter);
        jwtConverter.setPrincipalClaimName("sub"); // Use subject as principal name
        return jwtConverter;
    }

    @Bean
    SecurityFilterChain resourceServer(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**", "/userinfo")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/userinfo").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                        .accessDeniedHandler(new BearerTokenAccessDeniedHandler())
                );

        return http.build();
    }

}
