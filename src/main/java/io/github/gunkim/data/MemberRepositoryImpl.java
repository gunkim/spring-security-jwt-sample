package io.github.gunkim.data;

import io.github.gunkim.domain.Member;
import io.github.gunkim.domain.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class MemberRepositoryImpl implements MemberRepository {
    private final MemberJpaRepository memberJpaRepository;

    @Override
    public Member save(Member member) {
        return memberJpaRepository.save(MemberEntity.from(member)).toDomain();
    }

    @Override
    public Optional<Member> findByUsername(String username) {
        return memberJpaRepository.findByUsername(username)
                .map(MemberEntity::toDomain);
    }
}
