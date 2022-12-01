package io.github.gunkim.application.spring.security.service;

import io.github.gunkim.application.persistence.MemberEntity;
import io.github.gunkim.application.persistence.MemberRepositoryImpl;
import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepositoryImpl memberRepositoryImpl;

    public CustomUserDetailsService(MemberRepositoryImpl memberRepositoryImpl) {
        this.memberRepositoryImpl = memberRepositoryImpl;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MemberEntity memberEntity = memberRepositoryImpl.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("해당 유저를 찾을 수 없습니다. username: %s".formatted(username)));

        Collection<SimpleGrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(memberEntity.getRole().getValue()));

        return new User(memberEntity.getUsername(), memberEntity.getPassword(), roles);
    }
}
