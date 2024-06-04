package com.captain.resourceserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.PasswordLookup;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {
    private static final String ROLES_CLAIM = "roles";

    @Value("${keyFile}")
    private String keyFile;

    @Value("${password}")
    private String password;

    @Value("${alias}")
    private String alias;

    @Bean
    JwtAuthenticationConverter jwtAuthConverter() {

        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName(ROLES_CLAIM);
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwtConfigurer -> jwtConfigurer.decoder(jwtDecoder(jwkSource()))));
        http.authorizeHttpRequests((authorizeRequests) -> authorizeRequests
                .requestMatchers(HttpMethod.GET, "/couponapi/coupons/{code:^[A-Z]*$}")
                .hasAnyRole("USER", "ADMIN")
                .requestMatchers(HttpMethod.POST, "/couponapi/coupons")
                .hasRole("ADMIN")
                .anyRequest().authenticated());
        return http.build();

    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet jwkSet = buildJWKSet();
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private JWKSet buildJWKSet(){
        KeyStore keyStore;
        try (InputStream fis = this.getClass().getClassLoader().getResourceAsStream(keyFile);) {
            keyStore = KeyStore.getInstance("pkcs12");
            keyStore.load(fis, alias.toCharArray());
            return JWKSet.load(keyStore, new PasswordLookup() {

                @Override
                public char[] lookupPassword(String name) {
                    return password.toCharArray();
                }
            });
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
