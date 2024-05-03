package com.th.jwtredisauth.domain.dto;


import com.th.jwtredisauth.domain.Authority;
import com.th.jwtredisauth.domain.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Getter
public class UserResponseDTO {
    private final Long id;
    private final String email;
    private final String authorities;

    private UserResponseDTO(Long id, String email, String authorities) {
        this.id = id;
        this.email = email;
        this.authorities = authorities;
    }

    public static UserResponseDTO of(User user) {
        return new UserResponseDTO(
                user.getId(),
                user.getEmail(),
                populateAuthorities(user.getAuthorities())
        );
    }

    private static String populateAuthorities(Set<Authority> collection) {
        Set<String> authoritiesSet = new HashSet<>();
        for (Authority authority : collection) {
            authoritiesSet.add(authority.getName());
        }
        return String.join(",", authoritiesSet);
    }
}
