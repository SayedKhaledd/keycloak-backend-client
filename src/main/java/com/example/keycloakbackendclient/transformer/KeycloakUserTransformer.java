package com.example.keycloakbackendclient.transformer;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import com.example.keycloakbackendclient.transformer.mapper.KeycloakUserMapper;
import lombok.AllArgsConstructor;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Component;

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
}
