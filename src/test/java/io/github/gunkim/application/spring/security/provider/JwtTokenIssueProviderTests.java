package io.github.gunkim.application.spring.security.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class JwtTokenIssueProviderTests {
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private UserDetailsService userDetailsService;

    @InjectMocks
    private JwtTokenIssueProvider sut;

    @Test
    void 인증에_성공한다() {
        var request = new UsernamePasswordAuthenticationToken("gunkim", "1234");
        var user = new User("gunkim", "encoded password 1234", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        when(userDetailsService.loadUserByUsername((String) request.getPrincipal()))
                .thenReturn(user);
        when(passwordEncoder.matches((CharSequence) request.getCredentials(), user.getPassword()))
                .thenReturn(true);

        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) sut.authenticate(request);

        assertAll(
                () -> assertThat(authentication.getPrincipal()).isEqualTo("gunkim"),
                () -> assertThat(authentication.getCredentials()).isNull(),
                () -> assertThat(authentication.getAuthorities()).containsExactly(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Test
    void authentication이_null이라면_예외가_발생한다() {
        assertThatThrownBy(() -> sut.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("authentication 발급 오류");
    }

    @Test
    void 검증_대상일_경우_true를_반환한다() {
        boolean isSupported = sut.supports(UsernamePasswordAuthenticationToken.class);

        assertThat(isSupported).isTrue();
    }

    @Test
    void 검증_대상이_아닐_경우_false를_반환한다() {
        boolean isSupported = sut.supports(Authentication.class);

        assertThat(isSupported).isFalse();
    }
}
