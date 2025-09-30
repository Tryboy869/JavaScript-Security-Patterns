# JavaScript Security Patterns - Complete Guide

## Introduction

This document provides comprehensive documentation of all security patterns included in this repository. Each pattern addresses specific vulnerabilities while maintaining code simplicity and performance.

**Origin:** These patterns are based on research conducted by Nexus Studio, applying Rust-level security principles to JavaScript without external dependencies.

## Pattern Categories

### 1. Input Validation & Sanitization
### 2. XSS Prevention  
### 3. Safe Dynamic Code Execution
### 4. Authentication & Session Security
### 5. Cryptographic Operations

---

## Pattern 1: Input Validation & Sanitization

### Problem Statement

User input is the primary attack vector for web applications. Without proper validation:
- Malicious scripts can be injected (XSS)
- Databases can be compromised (SQL/NoSQL injection)
- Application logic can be bypassed
- Resources can be exhausted (DoS)

### Solution Architecture

```
User Input → Type Validation → Length Check → Character Filter → Sanitization → Safe Output
```

### Core Functions

#### validateInput()
**Purpose:** Universal input validator with type checking and constraint enforcement

**Parameters:**
- `input` (any): Value to validate
- `rules` (object): Validation constraints
  - `type`: Expected data type
  - `maxLength`: Maximum allowed length
  - `allowedChars`: Regex pattern for permitted characters
  - `required`: Whether field is mandatory

**Returns:** Object with `isValid`, `value`, and `errors` properties

**Security Guarantees:**
- Type confusion prevention
- Buffer overflow protection
- Character injection blocking
- DoS mitigation via length limits

#### sanitizeHTML()
**Purpose:** Removes XSS vectors from HTML content

**Attack Vectors Blocked:**
- Script tag injection
- Event handler injection  
- JavaScript protocol URLs
- Data URI attacks
- CSS expression attacks
- Iframe/object/embed tags

**Performance:** O(n) where n = input length

### Real-World Usage

```javascript
// E-commerce product review
function submitReview(reviewData) {
    const validation = validateInput(reviewData.content, {
        type: 'string',
        maxLength: 2000,
        allowedChars: /^[a-zA-Z0-9\s.,!?'"()\-:;]+$/,
        required: true
    });
    
    if (validation.isValid) {
        const safe = sanitizeHTML(validation.value);
        saveToDatabase(safe);
    }
}
```

### Testing Requirements

- Type validation for all supported types
- Boundary testing for length limits
- XSS payload test suite (50+ vectors)
- Performance benchmarks for large inputs
- Edge case handling (null, undefined, special characters)

---

## Pattern 2: XSS Prevention

### Problem Statement

Cross-Site Scripting allows attackers to:
- Steal user sessions and cookies
- Deface websites
- Redirect users to malicious sites
- Install keyloggers
- Perform actions as the victim

### Solution Architecture

```
Untrusted Content → Context Detection → Appropriate Encoding → Safe Rendering
```

### Defense Layers

#### Layer 1: Input Sanitization
Remove dangerous content before storage

#### Layer 2: Output Encoding  
Encode data based on output context (HTML, JavaScript, URL, CSS)

#### Layer 3: Content Security Policy
Browser-level protection against unauthorized script execution

#### Layer 4: Safe DOM APIs
Use textContent instead of innerHTML where possible

### Core Functions

#### safeSetHTML()
**Purpose:** Safely set HTML content after sanitization

**Security Model:**
1. Sanitize input using whitelist approach
2. Remove all script execution vectors
3. Encode remaining special characters
4. Use innerHTML only after sanitization

#### createSafeFragment()
**Purpose:** Create DocumentFragment with sanitized content

**Benefits:**
- Allows batch DOM operations
- Maintains performance
- Ensures content safety

#### validateURL()
**Purpose:** Validate and sanitize URLs before use

**Blocked Protocols:**
- javascript:
- data:
- vbscript:
- file:
- Relative URLs to private networks

### Content Security Policy Helper

```javascript
CSP.generate({
    allowInlineScripts: false,
    allowInlineStyles: false,
    allowEval: false,
    trustedDomains: ['cdn.trusted.com']
});
```

**Generated Policy:**
- Blocks inline scripts by default
- Restricts script sources to trusted domains
- Prevents eval() and Function constructor
- Blocks object/embed tags
- Enforces HTTPS for resources

### Real-World Usage

```javascript
// Social media post rendering
function renderPost(postData) {
    const container = document.createElement('div');
    
    // Author name (text only - no XSS risk)
    const author = document.createElement('h3');
    safeSetText(author, postData.authorName);
    
    // Post content (allow basic formatting)
    const content = document.createElement('div');
    safeSetHTML(content, postData.content, {
        allowBasicFormatting: true,
        allowLinks: true,
        maxLength: 10000
    });
    
    container.appendChild(author);
    container.appendChild(content);
    return container;
}
```

---

## Pattern 3: Safe Dynamic Code Execution

### Problem Statement

eval() and its equivalents (Function constructor, setTimeout with string, etc.) allow arbitrary code execution:
- Direct security vulnerabilities
- Prototype pollution attacks
- Access to global scope
- Bypass of security measures

### Solution Architecture

```
User Expression → Pattern Validation → Whitelist Check → Sandboxed Execution → Result Validation
```

### Core Functions

#### secureEval()
**Purpose:** Evaluate mathematical/logical expressions safely

**Security Mechanisms:**
- Character whitelist (numbers, operators, parentheses only)
- Keyword blacklist (eval, Function, constructor, etc.)
- Strict mode enforcement
- Context isolation
- Result type validation

**Allowed Operations:**
- Basic arithmetic (+, -, *, /, %)
- Parentheses for precedence
- Math object functions (when whitelisted)
- parseInt/parseFloat (when whitelisted)

**Blocked:**
- Variable assignment
- Function definitions
- Object/Array constructors
- Prototype access
- Global object access

#### safeTemplate()
**Purpose:** Process templates without code execution

**Security Model:**
- Only simple variable substitution
- No expression evaluation
- Nested property access with validation
- HTML entity encoding of output

#### createSandbox()
**Purpose:** Create isolated execution environment

**Features:**
- Frozen context object
- No global access
- Whitelisted functions only
- Strict mode enforced

### Real-World Usage

```javascript
// User-defined spreadsheet formulas
function evaluateFormula(formula, cellData) {
    // Replace cell references (A1, B2, etc.) with values
    let expression = formula.replace(/=/g, '');
    expression = expression.replace(/([A-Z]\d+)/g, (match) => {
        return cellData[match] || 0;
    });
    
    // Evaluate safely with Math functions
    const result = secureEval(expression, { Math });
    
    if (result.success) {
        return result.value;
    } else {
        return '#ERROR!';
    }
}
```

---

## Pattern Integration Best Practices

### Defense in Depth

Always apply multiple security layers:

```javascript
function processUserContent(content) {
    // Layer 1: Input validation
    const validation = validateInput(content, {
        type: 'string',
        maxLength: 5000,
        required: true
    });
    
    if (!validation.isValid) {
        throw new Error('Validation failed');
    }
    
    // Layer 2: Sanitization
    const sanitized = sanitizeHTML(validation.value);
    
    // Layer 3: Safe rendering
    const element = document.getElementById('content');
    safeSetHTML(element, sanitized, {
        allowBasicFormatting: true
    });
    
    return sanitized;
}
```

### Context-Aware Security

Apply appropriate security measures based on data context:

```javascript
// HTML Context
element.textContent = escapeHTML(userData);

// JavaScript Context
const jsData = JSON.stringify(userData);

// URL Context  
const urlSafe = encodeURIComponent(userData);

// Attribute Context
element.setAttribute('data-user', escapeHTML(userData));
```

### Performance Optimization

Security doesn't have to be slow:

```javascript
// Cache sanitization results for repeated content
const sanitizationCache = new Map();

function cachedSanitize(html) {
    if (sanitizationCache.has(html)) {
        return sanitizationCache.get(html);
    }
    
    const sanitized = sanitizeHTML(html);
    sanitizationCache.set(html, sanitized);
    return sanitized;
}
```

---

## Security Testing Checklist

### Input Validation Testing
- [ ] Type confusion attacks
- [ ] Boundary conditions (empty, max length, overflow)
- [ ] Special character injection
- [ ] Unicode/encoding attacks
- [ ] Null byte injection

### XSS Testing
- [ ] Script tag variations
- [ ] Event handler injections
- [ ] JavaScript protocol URLs
- [ ] Data URI attacks
- [ ] CSS expression attacks
- [ ] DOM clobbering
- [ ] Prototype pollution

### eval() Alternative Testing
- [ ] Code injection attempts
- [ ] Constructor chain exploitation
- [ ] Prototype pollution via templates
- [ ] Scope escape attempts
- [ ] Resource exhaustion (ReDoS)

---

## License

MIT License - Original research by Nexus Studio (nexusstudio100@gmail.com)