package com.gun.app;

import com.gun.app.domain.Member;
import com.gun.app.domain.MemberRepository;
import com.gun.app.domain.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.sql.SQLException;
import java.util.stream.IntStream;

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