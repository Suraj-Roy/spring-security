# Spring Security: Complete Guide

## 1. What is Spring Security?

Spring Security is a powerful framework that **protects applications and microservices** from:
- 🚫 **Unauthorized access**
- 🛡️ **Security attacks** (CSRF, XSS, SQL Injection)
- 🔐 **Data breaches**

It provides comprehensive security services for Java applications with minimal configuration.

## 2. Core Security Concepts

### Authentication: "Who are you?"
- **Process**: Verifying user identity
- **Methods**: Username/Password, JWT tokens, OAuth, Biometrics
- **Result**: User credentials are validated

### Authorization: "What can you do?"
- **Process**: Determining user permissions
- **Methods**: Role-based (ROLE_USER, ROLE_ADMIN), Permission-based
- **Result**: Access granted/denied to resources

```
User Login → Authentication (Identity Check) → Authorization (Permission Check) → Access Resource
```

## 3. Spring Security Architecture

### The Big Picture
```
HTTP Request
    ↓
Servlet Container (Tomcat)
    ↓
DelegatingFilterProxy (Bridge)
    ↓
FilterChainProxy (Spring Security)
    ↓
Security Filter Chain
    ↓
Spring Application Context
```

### What Happens When You Add `spring-boot-starter-security`?

When you add this dependency:
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

**Behind the Scenes Magic:**
1. **Auto-configuration kicks in** - `SecurityAutoConfiguration` runs
2. **Default security enabled** - All endpoints protected
3. **Default user created** - Username: `user`, Password: generated and logged
4. **Security filter chain activated** - 15+ filters automatically registered
5. **Login/logout pages** - Default forms created

## 4. Key Components Deep Dive

### DelegatingFilterProxy: The Bridge

**Problem**: Servlet filters don't have access to Spring beans
**Solution**: DelegatingFilterProxy acts as a bridge

```java
// Servlet Filter (No Spring Context Access)
public class ServletFilter implements Filter {
    // ❌ Cannot inject @Autowired beans
    // ❌ No access to ApplicationContext
}

// Spring Security Solution
DelegatingFilterProxy → FilterChainProxy → Spring Security Filters (✅ Full Spring access)
```

**How it works:**
```
Servlet Container
    ↓
DelegatingFilterProxy (Registered as servlet filter)
    ↓ (Delegates to Spring-managed bean)
FilterChainProxy (Spring bean with @Autowired access)
    ↓
Security Filter Chain
```

### FilterChainProxy: The Security Orchestrator

```java
@Component
public class FilterChainProxy extends GenericFilterBean {
    
    private List<SecurityFilterChain> filterChains;
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        // 1. Match request to appropriate SecurityFilterChain
        // 2. Execute security filters in order
        // 3. Apply authentication and authorization
    }
}
```

**Filter Chain Example:**
```
1. SecurityContextPersistenceFilter
2. LogoutFilter  
3. UsernamePasswordAuthenticationFilter
4. BasicAuthenticationFilter
5. AuthorizationFilter
6. ExceptionTranslationFilter
```

## 5. Authentication Architecture

### Authentication Flow
```
User Credentials
    ↓
AuthenticationFilter
    ↓
AuthenticationManager (ProviderManager)
    ↓
AuthenticationProvider
    ↓
UserDetailsService + PasswordEncoder
    ↓
Authentication Object
    ↓
SecurityContext
```

### Key Players

#### 1. AuthenticationProvider
```java
public interface AuthenticationProvider {
    
    // Does the actual authentication
    Authentication authenticate(Authentication authentication) throws AuthenticationException;
    
    // Check if this provider supports the authentication type
    boolean supports(Class<?> authentication);
}
```

**Built-in Providers:**
- `DaoAuthenticationProvider` - Database authentication
- `JwtAuthenticationProvider` - JWT token authentication
- `LdapAuthenticationProvider` - LDAP authentication

#### 2. ProviderManager
```java
@Component
public class ProviderManager implements AuthenticationManager {
    
    private List<AuthenticationProvider> providers;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        for (AuthenticationProvider provider : providers) {
            if (provider.supports(authentication.getClass())) {
                return provider.authenticate(authentication);
            }
        }
        throw new ProviderNotFoundException("No provider found");
    }
}
```

#### 3. AbstractAuthenticationToken
```java
// Base class for all authentication tokens
public abstract class AbstractAuthenticationToken implements Authentication {
    private Object principal;           // User identifier
    private Object credentials;         // Password/token
    private Collection<GrantedAuthority> authorities; // Permissions
    private boolean authenticated;      // Auth status
}

// Common implementations:
// - UsernamePasswordAuthenticationToken
// - JwtAuthenticationToken  
// - RememberMeAuthenticationToken
```

### Authentication Methods

#### supports() Method
```java
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    
    @Override
    public boolean supports(Class<?> authentication) {
        // Only handle UsernamePasswordAuthenticationToken
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        
        // Custom authentication logic
        if (isValidUser(username, password)) {
            return new UsernamePasswordAuthenticationToken(username, password, getAuthorities(username));
        }
        throw new BadCredentialsException("Invalid credentials");
    }
}
```

#### authenticate() Method Flow
```java
public Authentication authenticate(Authentication auth) {
    // 1. Extract credentials
    String username = auth.getName();
    String password = (String) auth.getCredentials();
    
    // 2. Load user details
    UserDetails user = userDetailsService.loadUserByUsername(username);
    
    // 3. Verify password
    if (!passwordEncoder.matches(password, user.getPassword())) {
        throw new BadCredentialsException("Wrong password");
    }
    
    // 4. Create successful authentication
    return new UsernamePasswordAuthenticationToken(username, null, user.getAuthorities());
}
```

## 6. Password Security

### PasswordEncoder
```java
public interface PasswordEncoder {
    String encode(CharSequence rawPassword);           // Hash password
    boolean matches(CharSequence rawPassword, String encodedPassword); // Verify
}
```

**Modern Configuration:**
```java
@Configuration
public class SecurityConfig {
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt with strength 12 (more secure than default 10)
        return new BCryptPasswordEncoder(12);
    }
}
```

**Usage Example:**
```java
@Service
public class UserService {
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    public void createUser(String username, String rawPassword) {
        String encodedPassword = passwordEncoder.encode(rawPassword);
        // Save user with encoded password
    }
    
    public boolean validatePassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
```

## 7. Security Context Management

### SecurityContextHolder: The Security Vault
```java
// Thread-local storage for security information
public class SecurityContextHolder {
    
    // Get current user's authentication
    public static Authentication getAuthentication() {
        return getContext().getAuthentication();
    }
    
    // Set authentication (after successful login)
    public static void setAuthentication(Authentication auth) {
        getContext().setAuthentication(auth);
    }
    
    // Get security context
    public static SecurityContext getContext() {
        return strategy.getContext();
    }
}
```

### SecurityContext: The Container
```java
public interface SecurityContext {
    Authentication getAuthentication();
    void setAuthentication(Authentication authentication);
}
```

### SecurityContextPersistenceFilter: The Keeper
```java
@Component  
public class SecurityContextPersistenceFilter extends GenericFilterBean {
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        // 1. Load SecurityContext from session/repository
        SecurityContext context = securityContextRepository.loadContext(request);
        SecurityContextHolder.setContext(context);
        
        try {
            // 2. Process request
            chain.doFilter(request, response);
        } finally {
            // 3. Save SecurityContext back to session
            securityContextRepository.saveContext(context, request, response);
            SecurityContextHolder.clearContext();
        }
    }
}
```

## 8. Principal: The User Identity

### What is Principal?
```java
// Principal represents the authenticated user
public interface Principal {
    String getName(); // Usually username or email
}

// In Spring Security context
Authentication auth = SecurityContextHolder.getContext().getAuthentication();
Object principal = auth.getPrincipal(); // Can be UserDetails, String, or custom object

// Common usage in controllers
@GetMapping("/profile")
public String getProfile(Principal principal) {
    String username = principal.getName();
    // Load user profile
}
```

### Getting Current User Information
```java
@RestController
public class UserController {
    
    // Method 1: Using Principal
    @GetMapping("/me")
    public User getCurrentUser(Principal principal) {
        return userService.findByUsername(principal.getName());
    }
    
    // Method 2: Using Authentication
    @GetMapping("/details")
    public UserDetails getUserDetails(Authentication authentication) {
        return (UserDetails) authentication.getPrincipal();
    }
    
    // Method 3: Using SecurityContextHolder (anywhere in code)
    public String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return auth.getName();
    }
}
```

## 9. Putting It All Together: Complete Example

### Basic Security Configuration
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
            );
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean  
    public AuthenticationManager authManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
```

## Key Takeaways

### Security Architecture Summary
1. **DelegatingFilterProxy** bridges servlet filters and Spring beans
2. **FilterChainProxy** orchestrates security filter execution
3. **AuthenticationManager** coordinates multiple authentication providers
4. **SecurityContextHolder** maintains user session across requests
5. **PasswordEncoder** ensures secure password storage

### Best Practices
- Always use BCrypt or stronger password encoding
- Implement proper session management
- Use HTTPS in production
- Apply principle of least privilege
- Regularly update dependencies for security patches

This comprehensive guide gives you the foundation to secure your Spring Boot applications effectively!