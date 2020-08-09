package com.gun.app.security.service;

import com.gun.app.domain.Member;
import com.gun.app.domain.MemberRepository;
import com.gun.app.domain.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> optMember = memberRepository.findByUsername(username);
        if(!optMember.isPresent()){
            throw new UsernameNotFoundException("해당 유저를 찾을 수 없습니다. :::"+username);
        }
        Member member = optMember.get();
        Collection<SimpleGrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(member.getRole().getValue()));

        return new User(member.getUsername(), member.getPassword(), roles);
    }
}