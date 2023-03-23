package io.github.gunkim.application.spring.security;

import static java.util.stream.Collectors.toList;

import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SkipPathRequestMatcher implements RequestMatcher {
    private final OrRequestMatcher matchers;
    private final RequestMatcher processingMatcher;

    public SkipPathRequestMatcher(final List<String> pathsToSkip, final String processingPath) {
        if (pathsToSkip == null) {
            throw new IllegalArgumentException("pathsToSkip cannot be null");
        }
        List<RequestMatcher> matchers = pathsToSkip.stream().map(AntPathRequestMatcher::new).collect(toList());

        this.matchers = new OrRequestMatcher(matchers);
        this.processingMatcher = new AntPathRequestMatcher(processingPath);
    }

    @Override
    public boolean matches(final HttpServletRequest request) {
        if (matchers.matches(request)) {
            return false;
        }
        return processingMatcher.matches(request);
    }
}
