package io.github.gunkim.domain;

public enum Role {
    USER("일반 사용자", "ROLE_USER"),
    ADMIN("관리자", "ROLE_ADMIN");

    private final String title;
    private final String value;

    Role(String title, String value) {
        this.title = title;
        this.value = value;
    }

    public static Role of(String value) {
        for (Role role : values()) {
            if (role.value.equals(value)) {
                return role;
            }
        }
        throw new IllegalArgumentException("잘못된 권한입니다.");
    }

    public String title() {
        return title;
    }

    public String value() {
        return value;
    }
}
