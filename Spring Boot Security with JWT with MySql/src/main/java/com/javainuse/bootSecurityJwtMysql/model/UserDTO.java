package com.javainuse.bootSecurityJwtMysql.model;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class UserDTO {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}
