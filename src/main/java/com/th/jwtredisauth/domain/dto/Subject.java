package com.th.jwtredisauth.domain.dto;

import com.th.jwtredisauth.domain.Authority;
import lombok.Getter;

import java.util.Set;

@Getter
public class Subject {
    private final Long id;
    private final String email;
    private final String type;
    private final String authorities;

    private Subject(Long id, String email, String type, String authorities) {
        this.id = id;
        this.email = email;
        this.type = type;
        this.authorities = authorities;
    }

    public static Subject atk(Long id, String email, String authorities) {
        return new Subject(id, email, "ATK", authorities);
    }

    public static Subject rtk(Long id, String email, String authorities) {
        return new Subject(id, email, "RTK", authorities);
    }
}
