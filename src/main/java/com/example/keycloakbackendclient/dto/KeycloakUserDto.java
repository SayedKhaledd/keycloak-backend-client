package com.example.keycloakbackendclient.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Builder
@AllArgsConstructor
@Data
public class KeycloakUserDto {
    private String id;
    private String keycloakId;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private List<String> roles;
    private String password;
}
