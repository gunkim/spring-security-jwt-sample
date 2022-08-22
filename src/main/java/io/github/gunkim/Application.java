package io.github.gunkim;

import io.github.gunkim.domain.Member;
import io.github.gunkim.domain.MemberRepository;
import io.github.gunkim.domain.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.SQLException;

@SpringBootApplication
public class Application{
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
    @Bean
    public CommandLineRunner runner(MemberRepository memberRepository, PasswordEncoder passwordEncoder) throws SQLException {
        return (args) -> {
            Member userMember = memberRepository.save(
                    Member.builder()
                            .username("gunkim")
                            .password(passwordEncoder.encode("test"))
                            .role(Role.USER)
                            .build()
            );
        };
    }
}