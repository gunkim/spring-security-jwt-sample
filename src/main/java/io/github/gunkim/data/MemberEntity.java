package io.github.gunkim.data;

import io.github.gunkim.domain.Member;
import io.github.gunkim.domain.Role;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.experimental.Accessors;

@Entity
@Getter
@Accessors(fluent = true)
public class MemberEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String username;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    protected MemberEntity() {
    }

    public MemberEntity(String username, String password, Role role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public static MemberEntity from(Member member) {
        return new MemberEntity(member.username(), member.password(), member.role());
    }

    public Member toDomain() {
        return new Member(id, username, password, role);
    }
}
