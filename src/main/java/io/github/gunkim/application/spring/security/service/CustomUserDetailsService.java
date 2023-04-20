package io.github.gunkim.application.spring.security.service;

import io.github.gunkim.domain.MemberRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var member = memberRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("해당 유저를 찾을 수 없습니다. username: %s".formatted(username)));

        var roles = List.of(new SimpleGrantedAuthority(member.role().value()));
        return new User(member.username(), member.password(), roles);
    }
}
