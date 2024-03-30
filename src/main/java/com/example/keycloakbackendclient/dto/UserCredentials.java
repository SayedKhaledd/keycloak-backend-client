package com.example.keycloakbackendclient.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class UserCredentials {
    private String username;
    private String password;


}
