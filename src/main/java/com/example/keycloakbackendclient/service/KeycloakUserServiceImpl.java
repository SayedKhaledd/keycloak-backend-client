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
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

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

        CredentialRepresentation credentials = new CredentialRepresentation();
        credentials.setType(CredentialRepresentation.PASSWORD);
        credentials.setValue(keycloakUserDto.getPassword());
        credentials.setTemporary(false);

        userRepresentation.setCredentials(Collections.singletonList(credentials));
        userRepresentation.setEnabled(true);
        userRepresentation.setEmailVerified(true);

        try (Response response = usersResource.create(userRepresentation)) {
            if (response.getStatus() != 201) {
                log.error("KeycloakUserService: registerUser - error: {}", response.getStatus());
                throw new RuntimeException("Failed to create user, status: " + response.getStatus());
            }
            String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            UserResource userResource = usersResource.get(userId);

            addRealmRolesToUserResource(userResource, keycloakUserDto.getRoles());
            addRealmRolesToUserRepresentation(userRepresentation, userResource.roles().realmLevel().listAll());

            return keycloakUserTransformer.toKeycloakUserDto(userResource.toRepresentation());
        } catch (Exception e) {
            log.error("KeycloakUserService: registerUser - error: {}", e.getMessage());
            throw new RuntimeException("Error creating user", e);
        }

    }

    @Override
    public void updateUserRole(String keycloakId, String role) {
        log.info("KeycloakUserService: updateUserRole - was called with keycloakId: {} and role: {}", keycloakId, role);
        UsersResource usersResource = keycloakAdminClient.realm(realm).users();
        UserResource userResource = usersResource.get(keycloakId);
        userResource.roles().realmLevel().remove(userResource.roles().realmLevel().listAll());
        RoleRepresentation realmRole = keycloakAdminClient.realm(realm).roles().get(role).toRepresentation();

        userResource.roles().realmLevel().add(Collections.singletonList(realmRole));
    }

    @Override
    public void updateKeycloakUser(KeycloakUserDto keycloakUserDto) {
        log.info("KeycloakUserService: updateKeycloakUser - was called with user: {}", keycloakUserDto.getUsername());
        UsersResource usersResource = keycloakAdminClient.realm(realm).users();
        UserResource userResource = usersResource.get(keycloakUserDto.getKeycloakId());
        UserRepresentation userRepresentation = keycloakUserTransformer.toUserRepresentation(keycloakUserDto);
        userResource.update(userRepresentation);
    }

    @Override
    public void deleteUser(String keycloakId) {
        log.info("KeycloakUserService: deleteUser - was called with keycloakId: {}", keycloakId);
        UsersResource usersResource = keycloakAdminClient.realm(realm).users();
        UserResource userResource = usersResource.get(keycloakId);
        userResource.remove();
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
            return keycloakUserTransformer.toKeycloakUserDto(jwtAuthenticationToken);
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

    private void addRealmRolesToUserResource(UserResource userResource, List<String> roles) {
        roles.forEach(role -> {
            RoleRepresentation realmRole = keycloakAdminClient.realm(realm).roles().get(role).toRepresentation();
            userResource.roles().realmLevel().add(Collections.singletonList(realmRole));
        });
    }

    private void addRealmRolesToUserRepresentation(UserRepresentation userRepresentation, List<RoleRepresentation> realmRoles) {
        userRepresentation.setRealmRoles(realmRoles.stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList()));
    }

}
