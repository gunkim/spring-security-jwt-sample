package com.gun.app.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gun.app.domain.Role;
import com.gun.app.security.SkipPathRequestMatcher;
import com.gun.app.security.filter.AsyncLoginProcessingFilter;
import com.gun.app.security.filter.JwtTokenAuthenticationProcessingFilter;
import com.gun.app.security.provider.AsyncAuthenticationProvider;
import com.gun.app.security.provider.JwtAuthenticationProvider;
import com.gun.app.security.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;
import java.util.List;

/**
 * 스프링 시큐리티 설정을 위한 클래스
 */
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";
    public static final String AUTHENTICATION_URL = "/api/auth/login";
    public static final String API_ROOT_URL = "/api/**";

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final AsyncAuthenticationProvider asyncAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    private final ObjectMapper objectMapper;
    private final JwtUtil jwtUtil;

    /**
     * 시큐리티 설정
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<String> permitAllEndpointList = Arrays.asList(
                AUTHENTICATION_URL
        );
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
                .addFilterBefore(buildAsyncLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(permitAllEndpointList, API_ROOT_URL), UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * Provider 등록
     * @param auth
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(jwtAuthenticationProvider);
        auth.authenticationProvider(asyncAuthenticationProvider);
    }

    /**
     * 비동기 로그인 처리를 위한 필터 생성하고, authenticationManager를 등록해줌. 후에 반환.
     * @return
     * @throws Exception
     */
    private AsyncLoginProcessingFilter buildAsyncLoginProcessingFilter() throws Exception {
        AsyncLoginProcessingFilter filter = new AsyncLoginProcessingFilter(AUTHENTICATION_URL, objectMapper, successHandler, failureHandler);
        filter.setAuthenticationManager(this.authenticationManager());
        return filter;
    }

    /**
     * 토큰 검즈을 위한 필터 생성하고, authenticationManager를 등록해줌. 후에 반환.
     * @param pathsToSkip
     * @param pattern
     * @return
     * @throws Exception
     */
    private JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter(List<String> pathsToSkip, String pattern) throws Exception {
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, pattern);
        JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(matcher, failureHandler, jwtUtil);
        filter.setAuthenticationManager(this.authenticationManager());
        return filter;
    }
}