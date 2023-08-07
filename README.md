# Spring security with JWT
![Java](https://img.shields.io/badge/Java-17-red?logo=java)
![Spring Boot](https://img.shields.io/badge/SpringBoot-3.1.2-blue?logo=ktor)
![Gradle](https://img.shields.io/badge/gradle-7.4-blue?logo=gradle)
[![GitHub license](https://img.shields.io/github/license/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt)
[![GitHub issues](https://img.shields.io/github/issues/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt/issues)
[![GitHub forks](https://img.shields.io/github/forks/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt/fork)

스프링 시큐리티 이해도를 높이기 위해 전부 커스텀하여 구현했으나 [Spring Security OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html) JWT 구현체를 사용하면 기본 세팅으로 더 쉽게 사용이 가능하다.

2023년 8월 6일 기준 Spring Boot 3.X.X로 마이그레이션했으니 2.X.X 버전을 참고하고 싶다면 [이 곳](https://github.com/gunkim/springboot-security-jwt/tree/ce60a09d59d2790f663233d4a67c1287ddf938b8)을 참고하면 된다. 

# 개요

## 로그인 시
![1](https://user-images.githubusercontent.com/45007556/104460769-dbeaa780-55f1-11eb-9149-8d54a1c89c9e.png)

## 로그인 인증 시
![image](https://user-images.githubusercontent.com/45007556/104460703-c5dce700-55f1-11eb-8931-991164f48a52.png)

# AuthenticationManager는 Provider를 어떻게 할당 받을까?
스프링 시큐리티를 공부해 보면 AuthenticationManager는 AuthenticationProvider에게 실질적인 인증 처리를 위임한다고 한다.
하지만 지금까지 본 코드를 보았을 때 SecurityConfig를 통해 Provider를 등록해주는 코드는 있어도, Filter이나 AuthenticationManager에게 직접적으로 어떤 Provider를 쓸 것이라고 주입해주는 코드는 없다. 
## 둘 이상의 Provider가 전달된 경우 Authentication을 가지고 판단한다.
만약 여러 개의 Provider가 등록이 되어 있을 경우, AuthenticationManager는 어떻게 어떤 Provider에게 위임할 지를 결정할까?
AuthenticationManager을 구현한 ProviderManager [API 문서](https://docs.spring.io/spring-security/site/docs/4.2.15.RELEASE/apidocs/org/springframework/security/authentication/ProviderManager.html#authenticate-org.springframework.security.core.Authentication-) 를 보면 둘 이상의 Provider가 등록된 경우 Authentication을 처리할 수 있는 Provider를 찾아 할당한다고 한다.
## 로그인 처리 시 Filter-Provider 코드
```java
UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());
return this.getAuthenticationManager().authenticate(token);
```
```java
@Override
public boolean supports(Class<?> authentication) {
    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
}
```
## JWT 토큰 인증 시 Filter-Provider 코드

```java
return getAuthenticationManager().authenticate(new JwtAuthenticationToken(claimsJws));
```

```java
@Override
public boolean supports(Class<?> authentication) {
    return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
}
```
해당 소스들을 보면 supports에 지원하는 토큰 타입을 명시해 놓았다. 그래서 이것을 가지고 필터에서 전달하는 토큰 타입을 확인하여 Provider를 매칭해준다는 것을 알 수 있다.
