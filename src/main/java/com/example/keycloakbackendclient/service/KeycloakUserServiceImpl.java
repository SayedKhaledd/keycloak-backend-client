package com.example.keycloakbackendclient.service;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import com.example.keycloakbackendclient.dto.UserCredentials;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class KeycloakUserServiceImpl implements KeycloakUserService {

    private String realm;

    private String clientId;

    private String clientSecret;

    private String authServerUrl;

    public KeycloakUserServiceImpl(
            @Value("${keycloak.realm}") String realm,
            @Value("${keycloak.resource}") String clientId,
            @Value("${keycloak.credentials.secret}") String clientSecret,
            @Value("${keycloak.auth-server-url}") String authServerUrl) {
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authServerUrl = authServerUrl;
    }

    @Override
    public KeycloakUserDto registerUser(KeycloakUserDto keycloakUserDto) {
        return null;
    }

    @Override
    public String getAuthorizedUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return "System";
        } else if (authentication instanceof JwtAuthenticationToken) {
            return ((JwtAuthenticationToken) authentication).getToken().getClaim(StandardClaimNames.PREFERRED_USERNAME);
        } else
            return authentication.getName();

    }

    @Override
    public KeycloakUserDto getCurrentUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        } else if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;
            return KeycloakUserDto.builder()
                    .keycloakId(jwtAuthenticationToken.getToken().getClaim("sub"))
                    .username(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.PREFERRED_USERNAME))
                    .email(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.EMAIL))
                    .firstName(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.GIVEN_NAME))
                    .lastName(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.FAMILY_NAME))
                    .build();
        } else
            return null;
    }


    @Override
    public AccessTokenResponse generateAccessToken(UserCredentials credentials) {
        Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.PASSWORD)
                .username(credentials.getUsername())
                .password(credentials.getPassword())
                .build();
        return keycloak.tokenManager().getAccessToken();
    }
}
