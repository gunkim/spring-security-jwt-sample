package io.github.gunkim.application.spring.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.gunkim.application.spring.security.exception.AuthMethodNotSupportedException;
import io.github.gunkim.application.spring.security.model.LoginRequest;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@ExtendWith(MockitoExtension.class)
class JwtTokenIssueFilterTests {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    @Mock
    private AuthenticationFailureHandler authenticationFailureHandler;
    private JwtTokenIssueFilter sut;

    @BeforeEach
    void setup() {
        sut = new JwtTokenIssueFilter(
            "/login",
            new ObjectMapper(),
            authenticationSuccessHandler,
            authenticationFailureHandler
        );
        sut.setAuthenticationManager(authenticationManager);
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "PUT", "DELETE"})
    void Http_Method가_POST가_아니라면_예외가_발생한다(String method) {
        var request = new MockHttpServletRequest();
        request.setMethod(method);

        assertThatThrownBy(() -> sut.attemptAuthentication(request, null))
            .isInstanceOf(AuthMethodNotSupportedException.class)
            .hasMessage("Authentication method not supported");
    }

    @Test
    void 인증된_Authentication을_반환한다() throws IOException {
        LoginRequest loginRequest = new LoginRequest("gunkim", "1234");

        var request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setContent(new ObjectMapper().writeValueAsBytes(loginRequest));

        when(authenticationManager.authenticate(any(Authentication.class)))
            .thenReturn(new UsernamePasswordAuthenticationToken("gunkim", null, List.of()));

        var certedAuthentication = sut.attemptAuthentication(request, null);

        assertAll(
            () -> assertThat(certedAuthentication).isNotNull(),
            () -> assertThat(certedAuthentication.getPrincipal()).isEqualTo("gunkim"),
            () -> assertThat(certedAuthentication.isAuthenticated()).isTrue()
        );
    }
}
