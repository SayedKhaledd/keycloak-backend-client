package com.example.keycloakbackendclient.controller;

import com.example.keycloakbackendclient.dto.UserCredentials;
import com.example.keycloakbackendclient.service.KeycloakUserService;
import lombok.AllArgsConstructor;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/api")
public class KeycloakController {
    private final KeycloakUserService keycloakUserService;

    public KeycloakUserService getKeycloakUserService() {
        return keycloakUserService;
    }

    @PostMapping("/login")
    public AccessTokenResponse login(@RequestBody @Validated UserCredentials userCredentials) {
        return getKeycloakUserService().generateAccessToken(userCredentials);
    }
}
