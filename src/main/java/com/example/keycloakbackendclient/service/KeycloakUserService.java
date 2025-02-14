package com.example.keycloakbackendclient.service;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import com.example.keycloakbackendclient.dto.UserCredentials;
import org.keycloak.representations.AccessTokenResponse;

public interface KeycloakUserService {

    KeycloakUserDto registerUser(KeycloakUserDto keycloakUserDto);

    AccessTokenResponse generateAccessToken(UserCredentials credentials);

    String getAuthorizedUsername();

    void updateUserRole(String keycloakId, String role);

    void updateKeycloakUser(KeycloakUserDto keycloakUserDto);

    void deleteUser(String keycloakId);

    KeycloakUserDto getCurrentUser();
}
