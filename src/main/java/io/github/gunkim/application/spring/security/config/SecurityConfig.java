package io.github.gunkim.application.spring.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.SkipPathRequestMatcher;
import io.github.gunkim.application.spring.security.filter.AsyncLoginProcessingFilter;
import io.github.gunkim.application.spring.security.filter.JwtTokenAuthenticationProcessingFilter;
import io.github.gunkim.application.spring.security.provider.AsyncAuthenticationProvider;
import io.github.gunkim.application.spring.security.provider.JwtAuthenticationProvider;
import io.github.gunkim.application.spring.security.service.TokenService;
import io.github.gunkim.domain.Role;
import java.util.List;
import lombok.RequiredArgsConstructor;
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

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";
    public static final String AUTHENTICATION_URL = "/api/auth/login";
    public static final String API_ROOT_URL = "/api/**";

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final AsyncAuthenticationProvider asyncAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    private final ObjectMapper objectMapper;
    private final TokenService tokenService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationConfiguration configuration) throws Exception {
        http
                .csrf().disable()
                .exceptionHandling()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/say/adminHello").hasAnyRole(Role.ADMIN.name())
                .antMatchers("/api/say/userHello").hasAnyRole(Role.USER.name())
                .and()
                .addFilterBefore(buildAsyncLoginProcessingFilter(configuration.getAuthenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(List.of(AUTHENTICATION_URL), API_ROOT_URL,
                                configuration.getAuthenticationManager()),
                        UsernamePasswordAuthenticationFilter.class);

        http.authenticationProvider(jwtAuthenticationProvider);
        http.authenticationProvider(asyncAuthenticationProvider);

        return http.build();
    }

    private AsyncLoginProcessingFilter buildAsyncLoginProcessingFilter(AuthenticationManager authenticationManager) throws Exception {
        AsyncLoginProcessingFilter filter = new AsyncLoginProcessingFilter(AUTHENTICATION_URL, objectMapper, successHandler, failureHandler);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    private JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter(List<String> pathsToSkip, String pattern,
            AuthenticationManager authenticationManager) {
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, pattern);
        JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(matcher, failureHandler, tokenService);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }
}
