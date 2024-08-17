package com.example.keycloakbackendclient.service;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import com.example.keycloakbackendclient.dto.UserCredentials;
import lombok.AllArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@Service
public class KeycloakUserServiceImpl implements KeycloakUserService {

//    @Value("${keycloak.realm}")
//    private final String realm;
//
//    @Value("${keycloak.resource}")
//    private final String clientId;
//
//    @Value("${keycloak.credentials.secret}")
//    private final String clientSecret;
//
//    @Value("${keycloak.auth-server-url}")
//    private final String authServerUrl;


    @Override
    public KeycloakUserDto registerUser(KeycloakUserDto keycloakUserDto) {
        return null;
    }

    @Override
    public AccessTokenResponse generateAccessToken(UserCredentials credentials) {
//        Keycloak keycloak = KeycloakBuilder.builder()
//                .serverUrl(authServerUrl)
//                .realm(realm)
//                .clientId(clientId)
//                .clientSecret(clientSecret)
//                .username(credentials.getUsername())
//                .password(credentials.getPassword())
//                .grantType("password")
//                .build();
//        return keycloak.tokenManager().getAccessToken();
        return null;
    }
}
