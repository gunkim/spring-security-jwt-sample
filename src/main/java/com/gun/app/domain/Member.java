package com.gun.app.domain;

import lombok.*;

import javax.persistence.*;

/**
 * 사용자 테이블
 */
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
@Getter
@Entity
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String username;

    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder
    public Member(long id, String username, String password, Role role){
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
    }
}