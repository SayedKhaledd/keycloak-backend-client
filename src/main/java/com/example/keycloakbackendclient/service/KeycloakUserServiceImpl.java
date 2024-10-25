package com.example.keycloakbackendclient.service;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import com.example.keycloakbackendclient.dto.UserCredentials;
import com.example.keycloakbackendclient.transformer.KeycloakUserTransformer;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Service
public class KeycloakUserServiceImpl implements KeycloakUserService {

    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.resource}")
    private String clientId;
    @Value("${keycloak.credentials.secret}")
    private String clientSecret;
    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    private final Keycloak keycloakAdminClient;
    private final KeycloakUserTransformer keycloakUserTransformer;


    @Override
    public KeycloakUserDto registerUser(KeycloakUserDto keycloakUserDto) {
        log.info("KeycloakUserService: registerUser - was called with user: {}", keycloakUserDto.getUsername());
        UsersResource usersResource = keycloakAdminClient.realm(realm).users();
        UserRepresentation userRepresentation = keycloakUserTransformer.toUserRepresentation(keycloakUserDto);
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setValue(keycloakUserDto.getPassword());
        credentialRepresentation.setTemporary(false);
        userRepresentation.setCredentials(List.of(credentialRepresentation));

        try (Response response = usersResource.create(userRepresentation)) {
            if (response.getStatus() != 201) {
                throw new RuntimeException("Error creating user");
            }
            return keycloakUserTransformer.toKeycloakUserDto((UserRepresentation) response.getEntity());
        } catch (Exception e) {
            log.error("KeycloakUserService: registerUser - error: {}", e.getMessage());
            throw new RuntimeException("Error creating user" + e);
        }

    }

    @Override
    public String getAuthorizedUsername() {
        log.info("KeycloakUserService: getAuthorizedUsername - was called");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return "System";
        } else if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            return jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.PREFERRED_USERNAME);
        } else
            return authentication.getName();

    }

    @Override
    public KeycloakUserDto getCurrentUser() {
        log.info("KeycloakUserService: getCurrentUser - was called");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return null;
        } else if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
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
        log.info("KeycloakUserService: generateAccessToken - was called with credentials: {}", credentials.getUsername());
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
