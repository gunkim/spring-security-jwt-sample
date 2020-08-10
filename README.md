# 스프링 시큐리티와 JWT 연동 연습

# Gradle 의존성 추가
```gradle
dependencies {
    implementation group:'org.springframework.boot', name: 'spring-boot-starter-web'
    compileOnly group:'org.projectlombok', name: 'lombok'
    annotationProcessor group:'org.projectlombok', name: 'lombok'
    implementation group: 'org.springframework.boot', name: 'spring-boot-starter-security'
    implementation group: 'org.springframework.boot', name: 'spring-boot-starter-data-jpa'
    implementation group: 'com.h2database', name: 'h2'
    implementation group: 'io.jsonwebtoken', name: 'jjwt', version: '0.6.0'
}
```
# 개요
대충 흐름을 그려보았는데 아래와 같은 그림이 될 것 같다.

## 로그인 시
![](jwt-security-login.png)

## 로그인 인증 시
![](jwt-security-valid.png)

# AuthenticationManager는 Provider를 어떻게 할당 받을까?
스프링 시큐리티를 공부해 보면 AuthenticationManager는 AuthenticationProvider에게 실질적인 인증 처리를 위임한다고 한다.
하지만 지금까지 본 코드를 보았을 때 SecurityConfig를 통해 Provider를 등록해주는 코드는 있어도, Filter이나 AuthenticationManager에게 직접적으로 어떤 Provider를 쓸 것이라고 주입해주는 코드는 없다. 
## 둘 이상의 Provider가 전달된 경우 Authentication을 가지고 판단한다.
만약 여러 개의 Provider가 등록이 되어 있을 경우, AuthenticationManager는 어떻게 어떤 Provider에게 위임할 지를 결정할까?
AuthenticationManager을 구현한 ProviderManager [API 문서](https://docs.spring.io/spring-security/site/docs/4.2.15.RELEASE/apidocs/org/springframework/security/authentication/ProviderManager.html#authenticate-org.springframework.security.core.Authentication-) 를 보면 둘 이상의 Provider가 등록된 경우 Authentication을 처리할 수 있는 Provider를 찾아 할당한다고 한다.
## 비동기 로그인 처리 시 Filter-Provider 코드
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
```
return getAuthenticationManager().authenticate(new JwtAuthenticationToken(claimsJws));
```
```
@Override
public boolean supports(Class<?> authentication) {
    return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
}
```
해당 소스들을 보면 supports에 지원하는 토큰 타입을 명시해 놓았다. 그래서 이것을 가지고 필터에서 전달하는 토큰 타입을 확인하여 Provider를 매칭해준다는 것을 알 수 있다.