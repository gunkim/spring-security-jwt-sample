package com.gun.app.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gun.app.domain.Role;
import com.gun.app.security.SkipPathRequestMatcher;
import com.gun.app.security.filter.AsyncLoginProcessingFilter;
import com.gun.app.security.filter.JwtTokenAuthenticationProcessingFilter;
import com.gun.app.security.provider.AsyncAuthenticationProvider;
import com.gun.app.security.provider.JwtAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Arrays;
import java.util.List;

@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    public static final String AUTHENTICATION_HEADER_NAME = "Authorization";
    public static final String AUTHENTICATION_URL = "/api/auth/login";
    public static final String REFRESH_TOKEN_URL = "/api/auth/token";
    public static final String API_ROOT_URL = "/api/**";

    public final AuthenticationSuccessHandler successHandler;
    public final AuthenticationFailureHandler failureHandler;

    public final AsyncAuthenticationProvider asyncAuthenticationProvider;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public final ObjectMapper objectMapper;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        List<String> permitAllEndpointList = Arrays.asList(
                AUTHENTICATION_URL,
                REFRESH_TOKEN_URL
        );

        http
                .csrf().disable()
                .exceptionHandling()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .authorizeRequests()
//                .antMatchers("/api/say/adminHello").hasAnyRole(Role.ADMIN.name())
//                .antMatchers("/api/say/userHello").hasAnyRole(Role.ADMIN.name())
                .and()
                .addFilterBefore(buildAjaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(buildJwtTokenAuthenticationProcessingFilter(permitAllEndpointList, API_ROOT_URL), UsernamePasswordAuthenticationFilter.class);
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(jwtAuthenticationProvider);
        auth.authenticationProvider(asyncAuthenticationProvider);
    }
    private AsyncLoginProcessingFilter buildAjaxLoginProcessingFilter() throws Exception {
        AsyncLoginProcessingFilter filter = new AsyncLoginProcessingFilter(AUTHENTICATION_URL, objectMapper, successHandler, failureHandler);
        filter.setAuthenticationManager(this.authenticationManager());
        return filter;
    }
    private JwtTokenAuthenticationProcessingFilter buildJwtTokenAuthenticationProcessingFilter(List<String> pathsToSkip, String pattern) throws Exception {
        SkipPathRequestMatcher matcher = new SkipPathRequestMatcher(pathsToSkip, pattern);
        JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(matcher, failureHandler);
        filter.setAuthenticationManager(this.authenticationManager());
        return filter;
    }
}