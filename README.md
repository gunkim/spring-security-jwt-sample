# Spring security with JWT

![Java](https://img.shields.io/badge/Java-25-red?logo=openjdk)
![Spring Boot](https://img.shields.io/badge/SpringBoot-4.0.0--M3-blue?logo=springboot)
![Gradle](https://img.shields.io/badge/gradle-9.1-blue?logo=gradle)
[![GitHub license](https://img.shields.io/github/license/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt)
[![GitHub issues](https://img.shields.io/github/issues/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt/issues)
[![GitHub forks](https://img.shields.io/github/forks/gunkim/springboot-security-jwt)](https://github.com/gunkim/springboot-security-jwt/fork)

스프링 시큐리티 이해도를 높이기 위해 전부 커스텀하여 구현했으나 [Spring Security OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html) JWT 구현체를 사용하면 기본 세팅으로 더 쉽게 사용이 가능하다.

## 버전 이력

- **2025년 10월**: Java 25, Spring Boot 4.0.0-M3, Gradle 9.1로 메이저 버전 업데이트
  - Jackson ObjectMapper → JsonMapper 마이그레이션
- **2023년 8월**: Spring Boot 3.X.X로
  마이그레이션 ([2.X.X 버전 참고](https://github.com/gunkim/springboot-security-jwt/tree/ce60a09d59d2790f663233d4a67c1287ddf938b8))

## 기술 스택

- **Java 25**: 최신 Java LTS 버전
- **Spring Boot 4.0.0-M3**: 최신 Spring Boot 마일스톤 버전
- **JJWT 0.13.0**: JWT 토큰 생성 및 검증
- **Jackson 3.x (JsonMapper)**: JSON 직렬화/역직렬화
- **Spring Data JPA**: 데이터 영속성 관리
- **H2 Database**: 인메모리 데이터베이스
- **Gradle 9.1**: 빌드 도구

## 프로젝트 특징

- ✅ Spring Security 7 커스텀 필터 체인 구현
- ✅ JWT 기반 Stateless 인증
- ✅ 역할(Role) 기반 권한 관리
- ✅ schema.sql/data.sql 기반 데이터베이스 초기화

## 패키지 구조

```
src/main/java/io/github/gunkim
├── Application.java                          # Spring Boot 애플리케이션 진입점
├── domain/                                    # 도메인 엔티티 및 리포지토리
│   ├── Member.java                           # 회원 엔티티
│   ├── MemberRepository.java                 # 회원 리포지토리
│   └── Role.java                             # 권한 Enum
├── endpoint/                                  # REST API 컨트롤러
│   └── HomeController.java                   # 테스트용 엔드포인트
└── security/                                  # Spring Security 설정 및 구현
    ├── config/                                # 설정 클래스
    │   ├── JsonMapperConfig.java             # JsonMapper 빈 설정
    │   ├── PasswordConfig.java               # PasswordEncoder 빈 설정
    │   └── SecurityConfig.java               # Security 필터 체인 설정
    ├── exception/                             # 커스텀 예외
    │   ├── AuthMethodNotSupportedException.java
    │   └── JwtExpiredTokenException.java
    ├── filter/                                # 커스텀 필터
    │   ├── JwtTokenAuthenticationFilter.java # JWT 토큰 인증 필터
    │   ├── JwtTokenIssueFilter.java          # 로그인 처리 필터
    │   └── request/
    │       └── LoginRequest.java             # 로그인 요청 DTO
    ├── handler/                               # 인증 성공/실패 핸들러
    │   ├── CommonAuthenticationFailureHandler.java
    │   ├── JwtTokenIssueSuccessHandler.java
    │   └── response/
    │       ├── ErrorResponse.java            # 에러 응답 DTO
    │       └── TokenResponse.java            # 토큰 응답 DTO
    ├── provider/                              # 인증 제공자
    │   ├── JwtAuthenticationProvider.java    # JWT 토큰 인증 처리
    │   └── JwtTokenIssueProvider.java        # 로그인 인증 처리
    ├── service/                               # 비즈니스 로직
    │   ├── CustomUserDetailsService.java     # 사용자 정보 조회
    │   ├── TokenService.java                 # JWT 토큰 생성/파싱
    │   └── dto/
    │       └── TokenParserResponse.java      # 토큰 파싱 결과 DTO
    ├── JwtAuthenticationToken.java           # JWT 인증 토큰 객체
    └── SkipPathRequestMatcher.java           # 경로 매칭 유틸리티

src/main/resources/
├── application.yml                            # 애플리케이션 설정
├── schema.sql                                 # 데이터베이스 스키마 DDL
└── data.sql                                   # 초기 데이터 DML
```

## 시작하기

### 요구 사항

- Java 25 이상
- Gradle 9.1 이상

### 프로젝트 실행

```bash
# 프로젝트 빌드
./gradlew build

# 애플리케이션 실행
./gradlew bootRun
```

### 테스트 계정

프로젝트 시작 시 `data.sql`을 통해 자동으로 생성되는 계정입니다.

| Username | Password | Role  |
|----------|----------|-------|
| user     | 1234     | USER  |
| admin    | 1234     | ADMIN |

### API 테스트 예시

```bash
# 1. 로그인 (JWT 토큰 발급)
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"1234"}'

# 2. 인증이 필요한 API 호출
curl -X GET http://localhost:8080/api/say/user \
  -H "Authorization: Bearer {발급받은_JWT_토큰}"
```

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
