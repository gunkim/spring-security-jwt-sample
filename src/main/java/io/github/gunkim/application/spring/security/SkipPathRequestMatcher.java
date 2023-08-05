package io.github.gunkim.application.spring.security;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static java.util.stream.Collectors.toList;

public class SkipPathRequestMatcher implements RequestMatcher {
    private final OrRequestMatcher matchers;
    private final RequestMatcher processingMatcher;

    public SkipPathRequestMatcher(List<String> pathsToSkip, String processingPath) {
        if (pathsToSkip == null) {
            throw new IllegalArgumentException("pathsToSkip cannot be null");
        }
        this.matchers = new OrRequestMatcher(pathsToSkip.stream().map(AntPathRequestMatcher::new).collect(toList()));
        this.processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (matchers.matches(request)) {
            return false;
        }
        return processingMatcher.matches(request);
    }
}
