package io.github.gunkim;

import io.github.gunkim.application.persistence.MemberEntity;
import io.github.gunkim.application.persistence.MemberRepositoryImpl;
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
    public CommandLineRunner runner(MemberRepositoryImpl memberRepositoryImpl, PasswordEncoder passwordEncoder) throws SQLException {
        return (args) -> {
            MemberEntity userMemberEntity = memberRepositoryImpl.save(
                    MemberEntity.builder()
                            .username("gunkim")
                            .password(passwordEncoder.encode("test"))
                            .role(Role.USER)
                            .build()
            );
        };
    }
}