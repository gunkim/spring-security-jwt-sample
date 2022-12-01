package io.github.gunkim;

import io.github.gunkim.application.persistence.MemberEntity;
import io.github.gunkim.application.persistence.MemberRepositoryImpl;
import io.github.gunkim.domain.Role;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    public CommandLineRunner runner(MemberRepositoryImpl memberRepositoryImpl, PasswordEncoder passwordEncoder) {
        return __ -> memberRepositoryImpl.save(new MemberEntity("gunkim", passwordEncoder.encode("1234"), Role.USER));
    }
}
