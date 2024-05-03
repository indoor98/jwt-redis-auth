package com.th.jwtredisauth.service;

import com.th.jwtredisauth.domain.Authority;
import com.th.jwtredisauth.domain.User;
import com.th.jwtredisauth.domain.dto.SignInRequestDTO;
import com.th.jwtredisauth.domain.dto.SignUpRequestDTO;
import com.th.jwtredisauth.domain.dto.UserResponseDTO;
import com.th.jwtredisauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public UserResponseDTO signUp(SignUpRequestDTO signUpRequestDTO) {

        if (userRepository.existsByEmail(signUpRequestDTO.getEmail())) {
            throw new IllegalArgumentException("이미 존재하는 이메일입니다.");
        }

        // 비밀번호 유효성 검사
        String password = signUpRequestDTO.getPassword();
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("비밀번호는 최소 8자 이상이어야 합니다.");
        }

        String encodedPassword = passwordEncoder.encode(password);
        User user = User.builder()
                .email(signUpRequestDTO.getEmail())
                .password(encodedPassword)
                .build();

        Set<Authority> authorities = new HashSet<>();
        if (signUpRequestDTO.getAuthorities() != null) {
            for (String authorityName : signUpRequestDTO.getAuthorities()) {
                Authority authority = new Authority();
                authority.setName(authorityName);
                authority.setUser(user);
                authorities.add(authority);
            }
        }
        user.setAuthorities(authorities);
        userRepository.save(user);
        return UserResponseDTO.of(user);
    }

    @Transactional(readOnly = true)
    public UserResponseDTO signIn(SignInRequestDTO signInRequestDTO) {
        User user = userRepository.findByEmail(signInRequestDTO.getEmail())
                .orElseThrow(() -> null);

        boolean matches = passwordEncoder.matches(
                signInRequestDTO.getPassword(),
                user.getPassword());

        if(!matches) {
            return null;
        }
        return UserResponseDTO.of(user);
    }

}
