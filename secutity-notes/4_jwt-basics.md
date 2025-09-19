# Complete Guide to JWT (JSON Web Tokens)

## What is JWT?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.

### Key Characteristics:
- **Compact**: Can be sent via URL, POST parameter, or HTTP header
- **Self-contained**: Contains all necessary information about the user
- **Secure**: Digitally signed using a secret or public/private key pair

## Why Use JWT?

### Advantages:
- **Stateless**: No need to store session information on the server
- **Scalable**: Perfect for distributed systems and microservices
- **Cross-domain**: Can be used across different domains
- **Mobile-friendly**: Lightweight and easy to use in mobile applications
- **Industry standard**: Widely adopted and supported
- **Self-contained**: All user information is contained within the token

### Use Cases:
- Authentication and authorization
- Information exchange between services
- Single Sign-On (SSO) systems
- API authentication
- Mobile application authentication

## JWT Token Format

A JWT token consists of three parts separated by dots (`.`):

```
xxxxx.yyyyy.zzzzz
```

### Structure Breakdown:

#### 1. Header
Contains metadata about the token:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### 2. Payload (Claims)
Contains the actual data:
```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516325422
}
```

#### 3. Signature
Ensures the token hasn't been tampered with:
```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

### Complete Example:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

## JWT Authentication Flow

### Step-by-Step Process:

1. **User Login**
    - User provides credentials (username/password)
    - Server validates credentials against database

2. **Token Generation**
    - Server creates JWT token with user information
    - Token is signed with secret key

3. **Token Response**
    - Server sends JWT token back to client
    - Client stores token (localStorage, sessionStorage, or cookies)

4. **Subsequent Requests**
    - Client includes JWT in request headers
    - Server validates token signature
    - Server extracts user information from token

5. **Access Control**
    - Server grants/denies access based on token validity
    - No database lookup required for each request

### Flow Diagram:
```
Client                    Server                    Database
  |                        |                          |
  |---1. Login Request---->|                          |
  |                        |---2. Validate User----->|
  |                        |<--3. User Data----------|
  |<--4. JWT Token---------|                          |
  |                        |                          |
  |---5. API Request------>|                          |
  |   (with JWT)           |                          |
  |                        |---6. Verify JWT          |
  |<--7. Response----------|                          |
```

## Signature and Token Security

### Signing Algorithms:

#### HMAC (Symmetric)
- **HS256**: HMAC with SHA-256
- **HS384**: HMAC with SHA-384
- **HS512**: HMAC with SHA-512

#### RSA (Asymmetric)
- **RS256**: RSA with SHA-256
- **RS384**: RSA with SHA-384
- **RS512**: RSA with SHA-512

#### ECDSA (Asymmetric)
- **ES256**: ECDSA with SHA-256
- **ES384**: ECDSA with SHA-384
- **ES512**: ECDSA with SHA-512

### Security Best Practices:
- Use strong, unique secrets
- Implement short expiration times
- Use HTTPS for token transmission
- Validate all token claims
- Implement proper token revocation

## Token Approaches: JSON vs XML

### JSON Web Tokens (JWT)
**Advantages:**
- Compact and lightweight
- Native JavaScript support
- Human-readable
- Wide industry adoption
- Better performance

**Example:**
```json
{
  "sub": "user123",
  "name": "John Doe",
  "role": "admin",
  "exp": 1638360000
}
```

### XML-based Tokens (SAML)
**Advantages:**
- Rich metadata support
- Enterprise-grade features
- Complex assertion capabilities
- Strong schema validation

**Example:**
```xml
<saml:Assertion>
  <saml:Subject>
    <saml:NameID>user123</saml:NameID>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="role">
      <saml:AttributeValue>admin</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### Comparison Table:
| Feature | JWT (JSON) | SAML (XML) |
|---------|------------|------------|
| Size | Compact | Verbose |
| Parsing | Fast | Slower |
| Mobile Support | Excellent | Limited |
| Enterprise Features | Basic | Advanced |
| Browser Support | Native | Requires libraries |

## Database and Client Storage

### Server-Side Storage:
- **No session storage required** (stateless)
- Optional: Blacklist for revoked tokens
- User data remains in database
- Token validation happens in memory

### Client-Side Storage Options:

#### 1. localStorage
```javascript
// Store token
localStorage.setItem('jwt', token);

// Retrieve token
const token = localStorage.getItem('jwt');
```
**Pros:** Persistent across sessions
**Cons:** Vulnerable to XSS attacks

#### 2. sessionStorage
```javascript
// Store token
sessionStorage.setItem('jwt', token);

// Retrieve token
const token = sessionStorage.getItem('jwt');
```
**Pros:** Cleared when tab closes
**Cons:** Still vulnerable to XSS

#### 3. HTTP-Only Cookies
```javascript
// Set via server
res.cookie('jwt', token, { 
  httpOnly: true, 
  secure: true 
});
```
**Pros:** Protected from XSS
**Cons:** Vulnerable to CSRF attacks

#### 4. Memory Storage
```javascript
// In-memory variable
let authToken = null;
```
**Pros:** Most secure
**Cons:** Lost on page refresh

## JWT Expiry Time

### Common Expiration Patterns:

#### Short-lived Tokens (15 minutes - 1 hour)
```json
{
  "iat": 1638300000,
  "exp": 1638303600,
  "sub": "user123"
}
```

#### Medium-lived Tokens (1-24 hours)
```json
{
  "iat": 1638300000,
  "exp": 1638386400,
  "sub": "user123"
}
```

#### Long-lived Tokens (7-30 days)
```json
{
  "iat": 1638300000,
  "exp": 1638904800,
  "sub": "user123"
}
```

### Best Practices:
- Use short expiration times for sensitive operations
- Implement refresh token mechanism
- Consider user activity patterns
- Balance security with user experience

## Token Generation and Verification Process

### Token Generation Steps:

1. **Create Header**
```javascript
const header = {
  alg: 'HS256',
  typ: 'JWT'
};
```

2. **Create Payload**
```javascript
const payload = {
  sub: userId,
  name: userName,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
};
```

3. **Generate Signature**
```javascript
const signature = HMACSHA256(
  base64UrlEncode(header) + '.' + base64UrlEncode(payload),
  secret
);
```

4. **Combine Parts**
```javascript
const token = base64UrlEncode(header) + '.' + 
              base64UrlEncode(payload) + '.' + 
              signature;
```

### Token Verification Steps:

1. **Split Token**
```javascript
const [header, payload, signature] = token.split('.');
```

2. **Decode Header and Payload**
```javascript
const decodedHeader = JSON.parse(base64UrlDecode(header));
const decodedPayload = JSON.parse(base64UrlDecode(payload));
```

3. **Verify Signature**
```javascript
const expectedSignature = HMACSHA256(
  header + '.' + payload,
  secret
);
const isValid = expectedSignature === signature;
```

4. **Check Expiration**
```javascript
const isExpired = decodedPayload.exp < Math.floor(Date.now() / 1000);
```

## Handling Token Expiry

### Expiry Scenarios and Solutions:

#### 1. Client-Side Expiry Check
```javascript
function isTokenExpired(token) {
  const payload = JSON.parse(atob(token.split('.')[1]));
  return payload.exp < Math.floor(Date.now() / 1000);
}

// Usage
if (isTokenExpired(token)) {
  // Redirect to login or refresh token
  refreshToken();
}
```

#### 2. Server-Side Expiry Response
```javascript
// Server returns 401 Unauthorized
{
  "error": "Token expired",
  "code": "TOKEN_EXPIRED",
  "message": "Please refresh your token"
}
```

#### 3. Refresh Token Pattern
```javascript
// Client handles expiry
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      const refreshToken = getRefreshToken();
      const newToken = await refreshAccessToken(refreshToken);
      // Retry original request with new token
      return axios(error.config);
    }
    return Promise.reject(error);
  }
);
```

### Refresh Token Implementation:

#### Access Token + Refresh Token Pattern:
- **Access Token**: Short-lived (15 minutes)
- **Refresh Token**: Long-lived (7-30 days)

```javascript
// Initial login response
{
  "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refreshToken": "def50200e8a1d39...",
  "expiresIn": 900 // 15 minutes
}

// Refresh token request
POST /auth/refresh
{
  "refreshToken": "def50200e8a1d39..."
}

// Refresh token response
{
  "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expiresIn": 900
}
```

#### Automatic Token Refresh:
```javascript
// Set up automatic refresh before expiry
function scheduleTokenRefresh(expiresIn) {
  const refreshTime = (expiresIn - 60) * 1000; // Refresh 1 minute before expiry
  setTimeout(async () => {
    await refreshAccessToken();
    scheduleTokenRefresh(900); // Schedule next refresh
  }, refreshTime);
}
```

### Expiry Handling Best Practices:

1. **Graceful Degradation**: Redirect to login when tokens expire
2. **Silent Refresh**: Automatically refresh tokens in background
3. **User Notification**: Warn users before session expires
4. **Secure Storage**: Store refresh tokens securely
5. **Revocation Support**: Implement token blacklisting when needed

## Implementation Examples

### Node.js Token Generation:
```javascript
const jwt = require('jsonwebtoken');

function generateToken(user) {
  const payload = {
    sub: user.id,
    name: user.name,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
  };
  
  return jwt.sign(payload, process.env.JWT_SECRET);
}
```

### Node.js Token Verification:
```javascript
function verifyToken(token) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return { valid: true, payload: decoded };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}
```

### Frontend Token Usage:
```javascript
// Attach token to requests
axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

// Or for individual requests
fetch('/api/protected', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

## Conclusion

JWT provides a robust, scalable solution for authentication and authorization in modern applications.
By understanding its structure, implementing proper security measures, and handling token expiry gracefully, 
you can build secure and efficient authentication systems that work well across 
distributed architectures and various client platforms.