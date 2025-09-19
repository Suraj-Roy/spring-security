## Form-based vs Basic Authentication Comparison

### Form-based Authentication (Default Spring Security)
```java
// Default behavior when adding @EnableWebSecurity
http
    .formLogin(form -> form
        .loginPage("/login")                    // Custom login page
        .loginProcessingUrl("/perform_login")   // Form submission URL
        .usernameParameter("email")             // Custom username field name
        .passwordParameter("pwd")               // Custom password field name
        .defaultSuccessUrl("/dashboard", true)  // Redirect after successful login
        .failureUrl("/login?error=true")        // Redirect after failed login
        .permitAll()                           // Allow access to login page
    );
```

**Characteristics:**
- Uses `UsernamePasswordAuthenticationFilter`
- Shows HTML login form
- Session-based authentication
- Suitable for web applications with UI
- Redirects to login page for unauthenticated requests
- CSRF protection enabled by default

### Basic Authentication
```java
// API-focused configuration
http
    .httpBasic()
    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    .csrf().disable();
```

**Characteristics:**
- Uses `BasicAuthenticationFilter`
- Sends credentials in HTTP headers (`Authorization: Basic base64(username:password)`)
- Stateless authentication
- Ideal for APIs and backend services
- Returns 401 Unauthorized for unauthenticated requests
- No session management required

### When to Use Each

| Use Case | Form-based | Basic Auth |
|----------|------------|------------|
| Web Applications with UI | ✅ Ideal | ❌ Poor UX |
| REST APIs | ❌ Unnecessary | ✅ Perfect |
| Mobile Apps | ❌ Complex | ✅ Simple |
| Microservices | ❌ Stateful | ✅ Stateless |
| Development/Testing | ✅ Easy to use | ✅ Easy to test |
| Production APIs | ❌ Session overhead | ✅ Lightweight |

## Security Best Practices

### Production Security Considerations

#### 1. HTTPS is Mandatory
```java
// Force HTTPS in production
@Configuration
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .requiresChannel(channel -> 
                channel.requestMatchers("/**").requiresSecure())
            .httpBasic();
            
        return http.build();
    }
}
```

**Why HTTPS is Critical:**
- Basic Auth sends credentials in base64 (easily decoded)
- Without HTTPS, credentials are sent in plain text
- Man-in-the-middle attacks can intercept credentials

#### 2. Strong Password Policies
```java
@Component
public class PasswordValidator {
    
    public boolean isStrongPassword(String password) {
        return password.length() >= 12 &&
               password.matches(".*[A-Z].*") &&      // Uppercase
               password.matches(".*[a-z].*") &&      // Lowercase
               password.matches(".*\\d.*") &&        // Digit
               password.matches(".*[!@#$%^&*()].*");  // Special char
    }
}
```

#### 3. Account Security Features
```java
@Entity
public class Users implements UserDetails {
    
    private int failedLoginAttempts = 0;
    private LocalDateTime accountLockedUntil;
    private LocalDateTime lastPasswordChange;
    private boolean accountExpired = false;
    
    @Override
    public boolean isAccountNonLocked() {
        return accountLockedUntil == null || 
               LocalDateTime.now().isAfter(accountLockedUntil);
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        // Force password change every 90 days
        return lastPasswordChange != null && 
               lastPasswordChange.isAfter(LocalDateTime.now().minusDays(90));
    }
}
```

#### 4. Rate Limiting
```java
@Component
public class LoginAttemptService {
    
    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();
    private static final int MAX_ATTEMPTS = 3;
    
    public void loginSucceeded(String key) {
        attempts.remove(key);
    }
    
    public void loginFailed(String key) {
        attempts.merge(key, 1, Integer::sum);
    }
    
    public boolean isBlocked(String key) {
        return attempts.getOrDefault(key, 0) >= MAX_ATTEMPTS;
    }
}
```

### Security Headers Configuration
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .headers(headers -> headers
            .frameOptions().deny()                    // Prevent clickjacking
            .contentTypeOptions().and()               // Prevent MIME sniffing
            .xssProtection().and()                   // XSS protection
            .httpStrictTransportSecurity(hsts -> 
                hsts.maxAgeInSeconds(31536000)       // HSTS for 1 year
                    .includeSubdomains(true)
            )
            .and()
        );
        
    return http.build();
}
```

## Troubleshooting Common Issues

### 1. 401 Unauthorized Issues

**Symptoms:**
- Always receiving 401 even with correct credentials
- Credentials not being recognized

**Solutions:**
```java
// Check if user exists
@Override
public UserDetails loadUserByUsername(String username) {
    Users user = userRepository.findByUsername(username);
    if (user == null) {
        logger.error("User not found: " + username);
        throw new UsernameNotFoundException("User not found: " + username);
    }
    logger.info("User found: " + username);
    return user;
}

// Verify password encoding
@Component
public class PasswordDebugger {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public void debugPassword(String raw, String encoded) {
        boolean matches = passwordEncoder.matches(raw, encoded);
        logger.info("Raw: {} | Encoded: {} | Matches: {}", raw, encoded, matches);
    }
}
```

### 2. 403 Forbidden Issues

**Symptoms:**
- User authenticates but can't access resources
- Role-based access not working

**Solutions:**
```java
// Check role format
@Override
public Collection<? extends GrantedAuthority> getAuthorities() {
    // Must prefix with "ROLE_"
    return List.of(new SimpleGrantedAuthority("ROLE_" + role));
}

// Debug authorities
@GetMapping("/debug/authorities")
public ResponseEntity<Object> debugAuthorities(Authentication auth) {
    return ResponseEntity.ok(Map.of(
        "username", auth.getName(),
        "authorities", auth.getAuthorities(),
        "authenticated", auth.isAuthenticated()
    ));
}
```

### 3. H2 Console Access Issues
```java
// Allow H2 console specifically
.authorizeHttpRequests(authz -> authz
    .requestMatchers("/h2-console/**").permitAll()
    .anyRequest().authenticated()
)
.headers().frameOptions().sameOrigin() // Allow frames for H2 console
```

### 4. CSRF Issues with APIs
```java
// Disable CSRF for stateless APIs
http
    .csrf(csrf -> csrf
        .ignoringRequestMatchers("/api/**") // Ignore CSRF for API endpoints
    )
    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
```

### 5. Debug Logging
```properties
# Enable comprehensive security logging
logging.level.org.springframework.security=DEBUG# Spring Security Basic Authentication Tutorial

## Overview

This tutorial demonstrates how to implement Basic Authentication in Spring Security, moving from form-based authentication to HTTP Basic Authentication suitable for backend applications without UI components.

## Agenda

- Understanding Basic Authentication
- Implementing Basic Authentication
- Custom User Details Service
- Database Integration
- Complete Implementation Example

## What is Basic Authentication?

Basic Authentication is a simple authentication scheme built into the HTTP protocol. Unlike form-based authentication which shows a login page, Basic Authentication sends credentials in HTTP headers, making it ideal for:

- Backend services without UI
- RESTful APIs
- Mobile applications
- Microservices communication

## Spring Security Architecture Review

Spring Security uses a filter chain architecture:

```
Request → Security Filter Chain → Authentication Manager → Authentication Provider → User Details Service
```

Key components:
- **Security Filter Chain**: Processes security-related requests
- **Authentication Manager**: Coordinates authentication process
- **Authentication Provider**: Performs actual authentication
- **User Details Service**: Loads user data
- **Exception Translation Filter**: Handles authentication and authorization exceptions

## Form-based vs Basic Authentication

### Form-based Authentication (Default)
- Uses `UsernamePasswordAuthenticationFilter`
- Shows HTML login form
- Suitable for web applications with UI
- Session-based

### Basic Authentication
- Uses `BasicAuthenticationFilter`
- Sends credentials in HTTP headers
- Stateless
- Ideal for APIs and backend services

## Implementation Steps

### Step 1: Basic Configuration

Create a security configuration class:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .httpBasic() // Enable Basic Authentication
            .and()
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated() // Authenticate all requests
            );
        return http.build();
    }
}
```

### Step 2: Configure Custom Credentials

In `application.properties`:

```properties
spring.security.user.name=admin
spring.security.user.password=admin123
```

### Step 3: Create User Entity

```java
@Entity
public class Users implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String username;
    private String password;
    private String role;
    
    // Constructors, getters, setters
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role));
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

### Step 4: Create User Repository

```java
@Repository
public interface UserDetailsRepository extends JpaRepository<Users, Long> {
    Users findByUsername(String username);
}
```

### Step 5: Custom User Details Service

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserDetailsRepository userDetailsRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) 
            throws UsernameNotFoundException {
        Users user = userDetailsRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("Username not found: " + username);
        }
        return user;
    }
}
```

### Step 6: Complete Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public UserDetailsService userDetailsService() {
        return new CustomUserDetailsService();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);
        
        return new ProviderManager(authenticationProvider);
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .httpBasic()
            .and()
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/h2-console/**").permitAll() // Allow H2 console
                .anyRequest().authenticated()
            )
            .csrf().disable(); // Disable CSRF for APIs
            
        return http.build();
    }
}
```

## Password Encoder: Deep Dive

Password encoding is crucial for security - **never store plain text passwords**.

### Why Password Encoding Matters
- **Plain text passwords** = Security disaster if database is compromised
- **Encoded passwords** = Even if database is breached, passwords remain safe
- **BCrypt** adds salt automatically, making rainbow table attacks ineffective

### BCrypt: The Gold Standard
```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt with cost factor 12 (higher = more secure, slower)
        return new BCryptPasswordEncoder(12);
    }
}
```

### How BCrypt Works
```java
// Registration: Encoding password
String rawPassword = "mySecretPassword";
String encodedPassword = passwordEncoder.encode(rawPassword);
// Result: $2a$12$K8rLGGAZW5PX9V0X8VZ5ce5VaU5eDd5oP6qG.GZ5LpL5Z5Z5Z5Z5Ze

// Login: Verifying password  
boolean isValid = passwordEncoder.matches("mySecretPassword", encodedPassword); // true
boolean isInvalid = passwordEncoder.matches("wrongPassword", encodedPassword); // false
```

### Password Encoder Types
```java
// BCrypt (Recommended for most applications)
new BCryptPasswordEncoder(12); // Cost factor 12

// SCrypt (Memory-hard function)
new SCryptPasswordEncoder(16384, 8, 1, 32, 64);

// Argon2 (Most secure, latest standard)
new Argon2PasswordEncoder(16, 32, 1, 4096, 3);

// NEVER use these in production
new NoOpPasswordEncoder(); // Plain text - DANGEROUS!
new StandardPasswordEncoder(); // SHA-256 - DEPRECATED
```

### Cost Factor Considerations
```java
// Cost factor determines security vs performance
new BCryptPasswordEncoder(4);  // Fast, less secure
new BCryptPasswordEncoder(10); // Good balance (default)
new BCryptPasswordEncoder(12); // Higher security, slower
new BCryptPasswordEncoder(15); // Very secure, very slow
```

## Exception Translation Filter: Deep Dive

The `ExceptionTranslationFilter` is a critical component in Spring Security's filter chain that converts security exceptions into appropriate HTTP responses.

### Purpose and Responsibilities
- Catches `AccessDeniedException` and `AuthenticationException`
- Determines appropriate response for unauthenticated/unauthorized requests
- Triggers authentication process when needed
- Handles the conversion from Java exceptions to HTTP responses

### How it Works

```
Request → Security Filters → Exception Occurs
    ↓
ExceptionTranslationFilter catches exception
    ↓
Determines response type:
- AccessDeniedException → 403 Forbidden OR Redirect to login
- AuthenticationException → 401 Unauthorized OR Redirect to login
```

### Internal Implementation
```java
public class ExceptionTranslationFilter extends GenericFilterBean {
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
        try {
            chain.doFilter(request, response);
        } catch (AuthenticationException ex) {
            // User not authenticated
            handleAuthenticationException(request, response, ex);
        } catch (AccessDeniedException ex) {
            // User authenticated but lacks permission
            handleAccessDeniedException(request, response, ex);
        }
    }
    
    private void handleAuthenticationException() {
        // For API: Return 401 Unauthorized
        // For Web: Redirect to login page
    }
    
    private void handleAccessDeniedException() {
        // Return 403 Forbidden
        // Or redirect to access denied page
    }
}
```

### Exception Flow for Basic Authentication

When an unauthenticated request is made:
1. Request passes through security filters
2. If authentication is required but missing, an `AccessDeniedException` is thrown
3. `ExceptionTranslationFilter` catches this exception
4. Filter determines the request requires authentication
5. Sends appropriate response headers to client

### Response Headers
For Basic Authentication, the filter sends:
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Realm"
```

This tells the client:
- Authentication is required
- Use Basic Authentication method
- Realm information (optional security domain)

### Custom Exception Handling Configuration
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
                })
            );
        
        return http.build();
    }
}

## Authentication Flow

## Complete Authentication Flow: Step-by-Step

### Authentication Process Deep Dive
```
1. User Request with Credentials
   ↓
2. BasicAuthenticationFilter/UsernamePasswordAuthenticationFilter
   ↓
3. Create UsernamePasswordAuthenticationToken
   ↓
4. AuthenticationManager.authenticate()
   ↓
5. ProviderManager loops through AuthenticationProviders
   ↓
6. DaoAuthenticationProvider.authenticate()
   ↓
7. UserDetailsService.loadUserByUsername()
   ↓
8. PasswordEncoder.matches()
   ↓
9. Create successful Authentication object
   ↓
10. Store in SecurityContextHolder
```

### Code Flow Example
```java
// 1. Filter creates authentication token
UsernamePasswordAuthenticationToken authRequest = 
    new UsernamePasswordAuthenticationToken(username, password);

// 2. AuthenticationManager processes it
Authentication result = authenticationManager.authenticate(authRequest);

// 3. Store in SecurityContext
SecurityContextHolder.getContext().setAuthentication(result);
```

### 1. Unauthenticated Request
```http
GET /api/health HTTP/1.1
Host: localhost:8080
```

### 2. Exception Translation Filter Response
When no credentials are provided, `ExceptionTranslationFilter` catches the `AccessDeniedException` and responds:
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Realm"
```

### 3. Client Request with Credentials
Client receives the 401 response and sends credentials:
```http
GET /api/health HTTP/1.1
Host: localhost:8080
Authorization: Basic YWRtaW46YWRtaW4xMjM0
```

### 4. Server Processing
- `BasicAuthenticationFilter` extracts credentials from Authorization header
- Creates `UsernamePasswordAuthenticationToken`
- `AuthenticationManager` processes token
- `DaoAuthenticationProvider` validates credentials
- `CustomUserDetailsService` loads user from database
- `PasswordEncoder` verifies password
- If successful, stores authentication in `SecurityContextHolder`

### 5. Successful Response
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "healthy"
}
```

### 6. Authentication Failure Flow
If authentication fails:
- `AuthenticationException` is thrown
- `ExceptionTranslationFilter` catches it
- Returns 401 with appropriate error details

## Comprehensive Testing Guide

### Testing with Postman

#### 1. Public Endpoint (No Authentication)
- **Request**: GET `http://localhost:8080/api/public/hello`
- **Expected**: 200 OK with response message

#### 2. User Profile (Basic Auth Required)
- **Request**: GET `http://localhost:8080/api/users/profile`
- **Authorization**: Basic Auth
    - Username: `user`
    - Password: `user123`
- **Expected**: 200 OK with user profile JSON

#### 3. Admin Dashboard (Admin Role Required)
- **Request**: GET `http://localhost:8080/api/admin/dashboard`
- **Authorization**: Basic Auth
    - Username: `admin`
    - Password: `admin123`
- **Expected**: 200 OK with admin message

#### 4. Access Denied Test
- **Request**: GET `http://localhost:8080/api/admin/dashboard`
- **Authorization**: Basic Auth
    - Username: `user` (non-admin)
    - Password: `user123`
- **Expected**: 403 Forbidden

### Testing with cURL

```bash
# Public endpoint (no auth required)
curl http://localhost:8080/api/public/hello

# User endpoint (basic auth required)
curl -u user:user123 http://localhost:8080/api/users/profile

# Admin endpoint (admin role required)
curl -u admin:admin123 http://localhost:8080/api/admin/dashboard

# Should fail with 403
curl -u user:user123 http://localhost:8080/api/admin/dashboard

# Testing with explicit Authorization header
curl -H "Authorization: Basic dXNlcjp1c2VyMTIz" http://localhost:8080/api/users/profile

# Base64 encoding: echo -n "user:user123" | base64
```

### Testing Authentication Flow

```bash
# 1. Unauthenticated request (should return 401)
curl -v http://localhost:8080/api/users/profile

# Expected response:
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Basic realm="Realm"

# 2. Authenticated request (should return 200)
curl -v -u user:user123 http://localhost:8080/api/users/profile

# Expected response:
# HTTP/1.1 200 OK
# Content-Type: application/json
```

## Database Setup (H2 Example)

### Dependencies in pom.xml
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

## Advanced Configuration Options

### Request Matchers
```java
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .requestMatchers("/admin/**").hasRole("ADMIN")
    .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
    .anyRequest().authenticated()
)
```

### CORS Configuration
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(Arrays.asList("*"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
    configuration.setAllowedHeaders(Arrays.asList("*"));
    configuration.setAllowCredentials(true);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

### Multiple Authentication Providers
```java
@Bean
public AuthenticationManager authenticationManager(
        UserDetailsService userDetailsService,
        PasswordEncoder passwordEncoder) {
    
    DaoAuthenticationProvider daoProvider = new DaoAuthenticationProvider();
    daoProvider.setUserDetailsService(userDetailsService);
    daoProvider.setPasswordEncoder(passwordEncoder);
    
    // Add more providers if needed
    List<AuthenticationProvider> providers = Arrays.asList(daoProvider);
    
    return new ProviderManager(providers);
}
```

## Application Configuration

### Basic User Configuration (Development Only)
```properties
# application.properties

# Default user (for development/testing only - NOT for production)
spring.security.user.name=admin
spring.security.user.password=secret123
spring.security.user.roles=ADMIN

# Database configuration
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.username=sa  
spring.datasource.password=

# Enable H2 console
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# JPA Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true

# Logging (helpful for debugging)
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.security.web.FilterChainProxy=DEBUG
```

### YAML Configuration Alternative
```yaml
# application.yml
spring:
  security:
    user:
      name: admin
      password: secret123
      roles: ADMIN
      
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password: ""
    
  h2:
    console:
      enabled: true
      path: /h2-console

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.security.web.FilterChainProxy: DEBUG
```

## Complete Working Example

### Main Application Class
```java
@SpringBootApplication
public class BackendSecurityApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(BackendSecurityApplication.class, args);
    }
    
    // Initialize test data
    @Bean
    CommandLineRunner initData(UserDetailsRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                // Create admin user
                Users admin = new Users();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode("admin123"));
                admin.setRole("ROLE_ADMIN");
                userRepo.save(admin);
                
                // Create regular user  
                Users user = new Users();
                user.setUsername("user");
                user.setPassword(encoder.encode("user123"));
                user.setRole("ROLE_USER");
                userRepo.save(user);
                
                System.out.println("Test users created:");
                System.out.println("Admin: admin/admin123");
                System.out.println("User: user/user123");
            }
        };
    }
}
```

### Test Controller
```java
@RestController
@RequestMapping("/api")
public class TestController {
    
    @GetMapping("/public/hello")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("Hello from public endpoint! No authentication required.");
    }
    
    @GetMapping("/users/profile")
    public ResponseEntity<Map<String, Object>> userProfile(Authentication auth) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("username", auth.getName());
        profile.put("authorities", auth.getAuthorities());
        profile.put("authenticated", auth.isAuthenticated());
        return ResponseEntity.ok(profile);
    }
    
    @GetMapping("/admin/dashboard")  
    public ResponseEntity<String> adminDashboard() {
        return ResponseEntity.ok("Welcome to admin dashboard! Only admins can see this.");
    }
    
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("Application is healthy!");
    }
}
```

### Dependencies in pom.xml
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>
</dependencies>
```

### Application Properties
```properties
# H2 Database Configuration
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.driver-class-name=org.h2.Driver
spring.datasource.username=sa
spring.datasource.password=

# H2 Console (for development)
spring.h2.console.enabled=true
spring.h2.console.path=/h2-console

# JPA Configuration
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
```

## Security Considerations

### Password Encoding
- Always use strong password encoders (BCrypt, Argon2, PBKDF2)
- Never store passwords in plain text
- Consider password complexity requirements

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // Strength factor
}
```

### HTTPS
- Always use HTTPS in production
- HTTP Basic sends credentials in base64 (easily decoded)

### Session Management
```java
.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
)
```

### Security Headers
```java
.headers(headers -> headers
    .frameOptions().deny()
    .contentTypeOptions().and()
    .xssProtection().and()
    .httpStrictTransportSecurity(hsts -> 
        hsts.maxAgeInSeconds(31536000)
            .includeSubdomains(true)
    )
)
```

## Common Issues and Solutions

### 1. 401 Unauthorized
- Check username/password
- Verify user exists in database
- Confirm password encoding matches

### 2. 403 Forbidden
- Check user roles/authorities
- Verify request matchers configuration
- Confirm CSRF settings

### 3. H2 Console Access Issues
```java
.requestMatchers("/h2-console/**").permitAll()
.headers().frameOptions().sameOrigin() // Allow H2 console frames
```

## Debugging Tips

### Enable Debug Logging
```properties
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.security.web.FilterChainProxy=DEBUG
```

### Debug Points
Set breakpoints in:
- `BasicAuthenticationFilter.doFilterInternal()`
- `DaoAuthenticationProvider.authenticate()`
- `CustomUserDetailsService.loadUserByUsername()`

## Next Steps

This basic authentication setup provides foundation for:
- JWT-based authentication
- OAuth2 integration
- Role-based access control
- Method-level security
- Multi-factor authentication

## Complete Working Example

The implementation covers:
- ✅ Custom Security Configuration
- ✅ Database Integration (H2)
- ✅ Custom User Details Service
- ✅ Password Encoding
- ✅ Authentication Manager Setup
- ✅ Request Authorization
- ✅ CSRF Disabled for APIs

This provides a solid foundation for building secure REST APIs with Spring Security Basic Authentication.