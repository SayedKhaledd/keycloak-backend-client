package com.example.keycloakbackendclient.transformer.mapper;

import com.example.keycloakbackendclient.dto.KeycloakUserDto;
import org.keycloak.representations.idm.UserRepresentation;
import org.mapstruct.InjectionStrategy;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Map;

@Mapper(componentModel = "spring", injectionStrategy = InjectionStrategy.CONSTRUCTOR,
        unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface KeycloakUserMapper {


    @Mapping(target = "attributes", expression = "java(attributes(keycloakUserDto))")
    @Mapping(target = "realmRoles", source = "roles")
    @Mapping(target = "id", ignore = true)
    UserRepresentation toUserRepresentation(KeycloakUserDto keycloakUserDto);

    default Map<String, List<String>> attributes(KeycloakUserDto keycloakUserDto) {
        return Map.of("id", List.of(keycloakUserDto.getId()));
    }

    @Mapping(target = "keycloakId", source = "id")
    @Mapping(target = "roles", source = "realmRoles")
    @Mapping(target = "id", ignore = true)
    KeycloakUserDto toKeycloakUserDto(UserRepresentation userRepresentation);

}
