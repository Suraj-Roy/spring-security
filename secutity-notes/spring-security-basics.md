# Spring Security Authentication: Deep Dive

## 1. Exception Translation Filter

The **ExceptionTranslationFilter** handles security exceptions and converts them into appropriate HTTP responses.

### How It Works
```
Request → Security Filters → Exception Occurs
    ↓
ExceptionTranslationFilter catches exception
    ↓
Determines response type:
- AccessDeniedException → 403 Forbidden OR Redirect to login
- AuthenticationException → 401 Unauthorized OR Redirect to login
```

### Key Responsibilities
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

### Configuration Example
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
```

## 2. Password Encoder Deep Dive

### Why Password Encoding Matters
- **Plain text passwords** = Security disaster 💀
- **Encoded passwords** = Even if database is compromised, passwords are safe 🛡️

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
// BCrypt (Recommended)
new BCryptPasswordEncoder(12);

// SCrypt  
new SCryptPasswordEncoder(16384, 8, 1, 32, 64);

// Argon2 (Most secure)
new Argon2PasswordEncoder(16, 32, 1, 4096, 3);

// NEVER use these in production
new NoOpPasswordEncoder(); // Plain text - DANGEROUS!
new StandardPasswordEncoder(); // SHA-256 - DEPRECATED
```

## 3. Form-Based Authentication

### Default Spring Security Behavior
When you add `@EnableWebSecurity`, Spring automatically provides:
- Login page at `/login`
- Logout functionality at `/logout`
- Session management
- CSRF protection

### Configuration
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
        
        return http.build();
    }
}
```

### Custom Login Page
```html
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <form action="/perform_login" method="post">
        <div>
            <label>Email:</label>
            <input type="text" name="email" required/>
        </div>
        <div>
            <label>Password:</label>
            <input type="password" name="pwd" required/>
        </div>
        <div>
            <input type="submit" value="Login"/>
        </div>
        <!-- CSRF Token (Required) -->
        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
    </form>
</body>
</html>
```

## 4. Basic Authentication Filter

### How HTTP Basic Authentication Works
```
Client Request:
GET /api/users
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
                     ↑
                Base64 encoded "username:password"
```

### Configuration for Backend API
```java
@Configuration
@EnableWebSecurity  
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()                    // Disable CSRF for APIs
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Stateless
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")  
                .anyRequest().authenticated()
            )
            .httpBasic(); // Enable Basic Authentication
        
        return http.build();
    }
}
```

### Testing Basic Auth with curl
```bash
# Method 1: Direct credentials
curl -u username:password http://localhost:8080/api/users

# Method 2: Base64 encoded
curl -H "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=" http://localhost:8080/api/users
```

## 5. Backend Application Configuration

### Complete Backend Security Setup
```java
@Configuration
@EnableWebSecurity
public class BackendSecurityConfig {
    
    @Bean
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .cors().and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .authorizeHttpRequests(authz -> authz
                // Public endpoints
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll() // H2 database console
                
                // Admin endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                
                // User endpoints  
                .requestMatchers(HttpMethod.GET, "/api/users/profile").hasAnyRole("USER", "ADMIN")
                
                // All other requests need authentication
                .anyRequest().authenticated()
            )
            .httpBasic() // For API testing
            .headers().frameOptions().disable(); // For H2 console
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

## 6. Application Properties Configuration

### Basic User Configuration
```properties
# application.properties

# Default user (for development/testing only)
spring.security.user.name=admin
spring.security.user.password=secret123
spring.security.user.roles=ADMIN

# Database configuration
spring.datasource.url=jdbc:h2:mem:testdb
spring.datasource.username=sa  
spring.datasource.password=

# Enable H2 console
spring.h2.console.enabled=true

# Logging
logging.level.org.springframework.security=DEBUG
```

### YAML Configuration
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

logging:
  level:
    org.springframework.security: DEBUG
```

## 7. Authentication Flow Deep Dive

### Complete Authentication Process
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

## 8. Custom User Details Implementation

### UserDetails Interface
```java
public interface UserDetails {
    String getUsername();
    String getPassword();
    Collection<? extends GrantedAuthority> getAuthorities();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}
```

### Custom UserDetails Implementation
```java
@Entity
@Table(name = "users")
public class User implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true)
    private String username;
    
    private String password;
    
    private String email;
    
    @Enumerated(EnumType.STRING)
    private Role role;
    
    private boolean enabled = true;
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }
    
    @Override
    public boolean isAccountNonExpired() { return true; }
    
    @Override
    public boolean isAccountNonLocked() { return true; }
    
    @Override  
    public boolean isCredentialsNonExpired() { return true; }
    
    @Override
    public boolean isEnabled() { return enabled; }
    
    // Getters and setters...
}

enum Role {
    USER, ADMIN, MODERATOR
}
```

### Custom UserDetailsService
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        
        return user; // User implements UserDetails
    }
}
```

## 9. Complete Working Example

### Main Application Class
```java
@SpringBootApplication
public class BackendSecurityApplication {
    
    public static void main(String[] args) {
        SpringApplication.run(BackendSecurityApplication.class, args);
    }
    
    // Initialize some test data
    @Bean
    CommandLineRunner initData(UserRepository userRepo, PasswordEncoder encoder) {
        return args -> {
            if (userRepo.count() == 0) {
                User admin = new User();
                admin.setUsername("admin");
                admin.setPassword(encoder.encode("admin123"));
                admin.setEmail("admin@example.com");
                admin.setRole(Role.ADMIN);
                userRepo.save(admin);
                
                User user = new User();
                user.setUsername("user");
                user.setPassword(encoder.encode("user123"));
                user.setEmail("user@example.com");
                user.setRole(Role.USER);
                userRepo.save(user);
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
        return ResponseEntity.ok("Hello from public endpoint!");
    }
    
    @GetMapping("/users/profile")
    public ResponseEntity<String> userProfile(Authentication auth) {
        return ResponseEntity.ok("Hello " + auth.getName() + ", your role: " + auth.getAuthorities());
    }
    
    @GetMapping("/admin/dashboard")  
    public ResponseEntity<String> adminDashboard() {
        return ResponseEntity.ok("Welcome to admin dashboard!");
    }
}
```

### Testing Your API
```bash
# Public endpoint (no auth required)
curl http://localhost:8080/api/public/hello

# User endpoint (basic auth required)
curl -u user:user123 http://localhost:8080/api/users/profile

# Admin endpoint (admin role required)
curl -u admin:admin123 http://localhost:8080/api/admin/dashboard

# Should fail with 403
curl -u user:user123 http://localhost:8080/api/admin/dashboard
```

## Key Takeaways

### Security Best Practices for Backend APIs
1. **Always use HTTPS** in production
2. **Disable CSRF** for stateless APIs
3. **Use strong password encoding** (BCrypt with high cost)
4. **Implement proper exception handling**
5. **Use stateless sessions** for APIs
6. **Apply principle of least privilege**

### Development vs Production
- **Development**: Use `spring.security.user.*` properties for quick testing
- **Production**: Always implement custom UserDetailsService with database

This guide provides everything you need to secure your Spring Boot backend application! 🔒