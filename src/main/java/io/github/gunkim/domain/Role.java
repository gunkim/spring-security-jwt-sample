package io.github.gunkim.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 권한 관리
 */
@Getter
@AllArgsConstructor
public enum Role {
    USER("일반 사용자", "ROLE_USER"),
    ADMIN("관리자", "ROLE_ADMIN");

    private String title;
    private String value;
}
