# Spring Boot Filters: Complete Guide

## 1. What is a Filter?

A **Filter** is a Java component that intercepts HTTP requests and responses before they reach your controllers or after they leave them. Think of it as a security checkpoint or preprocessing station.

**Key Components:**
- **Filter Interface**: Your custom filters implement `javax.servlet.Filter`
- **Filter Chain**: Sequence of filters that process requests/responses
- **Dispatcher Servlet**: Spring's front controller that handles all HTTP requests
- **Servlet API**: Foundation that filters are built upon

**Filter Placement:**
```
Client Request → Filter1 → Filter2 → FilterN → Dispatcher Servlet → Controller
Client Response ← Filter1 ← Filter2 ← FilterN ← Dispatcher Servlet ← Controller
```

**Request Journey to Dispatcher Servlet:**
1. Client sends HTTP request
2. Filters process request in order (pre-processing)
3. Request reaches Dispatcher Servlet
4. Dispatcher Servlet routes to appropriate Controller
5. Controller processes and returns response
6. Response travels back through filters in reverse order (post-processing)
7. Final response sent to client

## 2. Understanding Filter Chain

The filter chain works like a pipeline where each filter can:
- Modify the request before passing it to the next filter
- Process the response after receiving it from the next filter
- Short-circuit the chain by not calling `chain.doFilter()`

**Request Flow:**
```
HTTP Request
    ↓
Security Filter (Authentication/Authorization)
    ↓
Logging Filter (Request logging)
    ↓
CORS Filter (Cross-origin handling)
    ↓
Custom Business Filter
    ↓
Dispatcher Servlet
    ↓
Controller Method
```

**Filter Chain Execution:**
```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
    // PRE-PROCESSING (before request reaches next filter/servlet)
    System.out.println("Before processing request");
    
    // Pass request to next filter in chain
    chain.doFilter(request, response);
    
    // POST-PROCESSING (after response comes back)
    System.out.println("After processing response");
}
```

## 3. Custom Filter Implementation

### Basic Custom Filter

```java
@Component
@Order(1) // Execution order
public class CustomLoggingFilter implements Filter {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomLoggingFilter.class);
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialize filter (called once)
        logger.info("CustomLoggingFilter initialized");
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        
        // PRE-PROCESSING
        long startTime = System.currentTimeMillis();
        String method = httpRequest.getMethod();
        String uri = httpRequest.getRequestURI();
        
        logger.info("Incoming request: {} {}", method, uri);
        
        try {
            // Continue filter chain
            chain.doFilter(request, response);
        } finally {
            // POST-PROCESSING
            long duration = System.currentTimeMillis() - startTime;
            int status = httpResponse.getStatus();
            logger.info("Completed request: {} {} - Status: {} - Duration: {}ms", 
                       method, uri, status, duration);
        }
    }
    
    @Override
    public void destroy() {
        // Cleanup resources (called once)
        logger.info("CustomLoggingFilter destroyed");
    }
}
```

### Registration Methods

**Method 1: Using @Component + @Order**
```java
@Component
@Order(1)
public class MyFilter implements Filter {
    // Implementation
}
```

**Method 2: Using FilterRegistrationBean**
```java
@Configuration
public class FilterConfig {
    
    @Bean
    public FilterRegistrationBean<CustomLoggingFilter> loggingFilter() {
        FilterRegistrationBean<CustomLoggingFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new CustomLoggingFilter());
        registrationBean.addUrlPatterns("/api/*"); // Specific URL patterns
        registrationBean.setOrder(1);
        return registrationBean;
    }
}
```

## 4. Security Filters Overview

Spring Security provides several built-in filters that form a security filter chain:

### Common Security Filters (in typical execution order):

1. **SecurityContextPersistenceFilter**
    - Loads/stores SecurityContext between requests
    - Manages session-based authentication

2. **UsernamePasswordAuthenticationFilter**
    - Handles form-based login authentication
    - Processes username/password credentials

3. **BasicAuthenticationFilter**
    - Handles HTTP Basic Authentication
    - Processes Authorization header

4. **BearerTokenAuthenticationFilter**
    - Handles JWT/OAuth2 token authentication
    - Processes Bearer tokens

5. **AuthorizationFilter**
    - Handles access control decisions
    - Checks if authenticated user has required permissions

6. **ExceptionTranslationFilter**
    - Handles security exceptions
    - Redirects to login page or returns 403/401

### Custom Security Filter Example

```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        
        // Check if Authorization header is present and valid
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // Extract JWT token
        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);
        
        // Validate token and set authentication
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### Registering Custom Security Filter

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthFilter;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

## Key Points for Spring Boot Development

### Filter vs Interceptor
- **Filters**: Servlet-level, work with all requests, can modify request/response
- **Interceptors**: Spring MVC-level, work only with controller requests, cannot modify request/response body

### Best Practices
1. **Use @Order** to control filter execution sequence
2. **Always call chain.doFilter()** unless you want to short-circuit
3. **Handle exceptions** properly to avoid breaking the chain
4. **Use OncePerRequestFilter** for filters that should execute only once per request
5. **Keep filters lightweight** as they execute for every request

### Common Use Cases
- **Authentication/Authorization** (Security filters)
- **Request/Response logging** (Audit trails)
- **CORS handling** (Cross-origin requests)
- **Rate limiting** (API throttling)
- **Request/Response modification** (Header manipulation)
- **Performance monitoring** (Response time tracking)

This guide provides a solid foundation for understanding and implementing filters in Spring Boot applications!