package io.github.gunkim.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class JsonMapperConfig {
    @Bean
    public JsonMapper jsonMapper() {
        return JsonMapper.builder().build();
    }
}
