package io.github.gunkim.data;

import io.github.gunkim.domain.Member;
import io.github.gunkim.domain.MemberRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public class MemberRepositoryImpl implements MemberRepository {
    private final MemberJpaRepository memberJpaRepository;

    public MemberRepositoryImpl(MemberJpaRepository memberJpaRepository) {
        this.memberJpaRepository = memberJpaRepository;
    }

    @Override
    public Member save(Member member) {
        return memberJpaRepository.save(MemberEntity.from(member)).toDomain();
    }

    @Override
    public Optional<Member> findByUsername(String username) {
        return memberJpaRepository.findByUsername(username).map(MemberEntity::toDomain);
    }
}
