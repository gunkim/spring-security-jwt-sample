package io.github.gunkim.application.spring.security.service.dto;

import io.github.gunkim.domain.Role;
import java.util.List;

public record TokenParserResponse(String username, List<Role> roles) {
}
