package io.github.gunkim.data;

import io.github.gunkim.domain.Member;
import io.github.gunkim.domain.Role;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

@Entity
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

    public long id() {
        return id;
    }

    public String username() {
        return username;
    }

    public String password() {
        return password;
    }

    public Role role() {
        return role;
    }
}