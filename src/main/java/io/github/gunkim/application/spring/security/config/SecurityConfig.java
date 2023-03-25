package io.github.gunkim.application.spring.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.SkipPathRequestMatcher;
import io.github.gunkim.application.spring.security.filter.JwtTokenAuthenticationFilter;
import io.github.gunkim.application.spring.security.filter.JwtTokenIssueFilter;
import io.github.gunkim.application.spring.security.provider.JwtAuthenticationProvider;
import io.github.gunkim.application.spring.security.provider.JwtTokenIssueProvider;
import io.github.gunkim.domain.Role;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig {

    public static final String AUTHENTICATION_URL = "/api/auth/login";
    public static final String API_ROOT_URL = "/api/**";

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final JwtTokenIssueProvider jwtTokenIssueProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    private final ObjectMapper objectMapper;

    public SecurityConfig(final AuthenticationSuccessHandler successHandler,
        final AuthenticationFailureHandler failureHandler, final JwtTokenIssueProvider jwtTokenIssueProvider,
        final JwtAuthenticationProvider jwtAuthenticationProvider, final ObjectMapper objectMapper) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.jwtTokenIssueProvider = jwtTokenIssueProvider;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
        this.objectMapper = objectMapper;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(final HttpSecurity http,
        final AuthenticationConfiguration configuration) throws Exception {
        final var authenticationManager = configuration.getAuthenticationManager();

        http.csrf().disable()
            .exceptionHandling()
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            .antMatchers("/api/say/adminHello").hasAnyRole(Role.ADMIN.name())
            .antMatchers("/api/say/userHello").hasAnyRole(Role.USER.name())
            .and()
            .addFilterBefore(jwtTokenIssueFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtTokenAuthenticationFilter(List.of(AUTHENTICATION_URL), authenticationManager), UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(jwtAuthenticationProvider);
        http.authenticationProvider(jwtTokenIssueProvider);

        return http.build();
    }

    private JwtTokenIssueFilter jwtTokenIssueFilter(final AuthenticationManager authenticationManager) {
        final var filter = new JwtTokenIssueFilter(AUTHENTICATION_URL, objectMapper, successHandler, failureHandler);
        filter.setAuthenticationManager(authenticationManager);

        return filter;
    }

    private JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter(final List<String> pathsToSkip,
        final AuthenticationManager authenticationManager) {
        final var matcher = new SkipPathRequestMatcher(pathsToSkip, API_ROOT_URL);

        final var filter = new JwtTokenAuthenticationFilter(matcher, failureHandler);
        filter.setAuthenticationManager(authenticationManager);

        return filter;
    }
}
