package com.base.service;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

/**
 * @author YISivlay
 */
@Component
public class JwtCustomizerService implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            var authorities = context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority).toList();
            context.getClaims().claim("authorities", authorities);
        }
    }
}
