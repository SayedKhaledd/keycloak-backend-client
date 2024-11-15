package com.example.keycloakbackendclient.transformer;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import com.example.keycloakbackendclient.transformer.mapper.KeycloakUserMapper;
import com.nimbusds.jose.shaded.gson.internal.LinkedTreeMap;
import lombok.AllArgsConstructor;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;

@AllArgsConstructor
@Component
public class KeycloakUserTransformer {

    private final KeycloakUserMapper keycloakUserMapper;

    public UserRepresentation toUserRepresentation(KeycloakUserDto keycloakUserDto) {
        return keycloakUserMapper.toUserRepresentation(keycloakUserDto);
    }

    public KeycloakUserDto toKeycloakUserDto(UserRepresentation userRepresentation) {
        return keycloakUserMapper.toKeycloakUserDto(userRepresentation);
    }

    public KeycloakUserDto toKeycloakUserDto(JwtAuthenticationToken jwtAuthenticationToken) {
        return KeycloakUserDto.builder()
                .keycloakId(jwtAuthenticationToken.getToken().getClaim("sub"))
                .username(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.PREFERRED_USERNAME))
                .email(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.EMAIL))
                .firstName(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.GIVEN_NAME))
                .lastName(jwtAuthenticationToken.getToken().getClaim(StandardClaimNames.FAMILY_NAME))
                .roles(getRoles(jwtAuthenticationToken))
                .build();
    }

    private List<String> getRoles(JwtAuthenticationToken jwtAuthenticationToken) {
        LinkedTreeMap<String, List<String>> realmAccess = jwtAuthenticationToken.getToken().getClaim("realm_access");
        return realmAccess.get("roles");
    }
}
