package com.th.jwtredisauth.config.filter;

import com.th.jwtredisauth.domain.Authority;
import com.th.jwtredisauth.domain.User;
import com.th.jwtredisauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * 원래 스프링 시큐리티를 사용하려면 UsernamePasswordAuthentication이 인증객체(User)를 인식하기 위해
 * 폼로그인 형식을 사용할 경우에만 이 필털르 거치게 됩니다.
 * 따라서 우리는 JWT사용중이므로 필요없습니다. 지워도 무관!!!
 */

@RequiredArgsConstructor
@Component
public class CustomUsernamePasswordAuthenticationProvider implements AuthenticationProvider {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        User user = userRepository.findByEmail(username).orElseThrow( () -> new BadCredentialsException("No User registered with this details!"));


        if(passwordEncoder.matches(password, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, getGrantedAuthorities(user.getAuthorities()));
        } else {
            throw new BadCredentialsException("Invalid Password <- 이거 이렇게 보내도 되나?");
        }
    }

    private List<GrantedAuthority> getGrantedAuthorities(Set<Authority> authorities) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Authority authority: authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority.getName()));
        }
        return grantedAuthorities;
    }

    // 얘는 무슨 역할을 수행하는지 모르게씁니다.
    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
