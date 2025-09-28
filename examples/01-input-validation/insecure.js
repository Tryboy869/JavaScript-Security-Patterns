/**
 * INSECURE INPUT VALIDATION EXAMPLES
 * 
 * WARNING: These examples demonstrate vulnerable code patterns.
 * DO NOT USE IN PRODUCTION - For educational purposes only.
 * 
 * Educational resource by Nexus Studio - nexusstudio100@gmail.com
 */

/**
 * VULNERABILITY #1: No Input Validation
 * Problem: Direct use of user input without any checks
 * Attack Vector: Injection attacks, type confusion, DoS
 */
function processUserDataInsecure(input) {
    // DANGEROUS: Direct use without validation
    return `<div>Hello ${input}</div>`;
}

// Attack example:
// processUserDataInsecure("<script>alert('XSS')</script>")
// Result: XSS vulnerability - script executes in browser

/**
 * VULNERABILITY #2: Weak Type Checking
 * Problem: Using loose equality and typeof checks incorrectly
 * Attack Vector: Type confusion, injection through type coercion
 */
function validateEmailInsecure(email) {
    // DANGEROUS: Weak validation
    if (email && email.includes('@')) {
        return true;  // Accepts malicious payloads
    }
    return false;
}

// Attack examples:
// validateEmailInsecure("<script>@evil.com") // Passes validation
// validateEmailInsecure("@<img src=x onerror=alert(1)>") // Passes validation

/**
 * VULNERABILITY #3: Direct DOM Manipulation
 * Problem: Using innerHTML with user-controlled content
 * Attack Vector: XSS through HTML injection
 */
function displayUserContentInsecure(element, userContent) {
    // DANGEROUS: innerHTML with unsanitized input
    element.innerHTML = userContent;
}

// Attack example:
// displayUserContentInsecure(div, "<img src=x onerror=alert('Hacked')>")
// Result: JavaScript executes in user's browser

/**
 * VULNERABILITY #4: Insufficient Length Checks
 * Problem: No bounds checking on input size
 * Attack Vector: DoS through memory exhaustion, buffer overflows
 */
function processLongTextInsecure(text) {
    // DANGEROUS: No length limits
    const processed = text.repeat(1000); // Can cause memory exhaustion
    return processed.toUpperCase(); // Memory intensive operation
}

// Attack example:
// processLongTextInsecure("A".repeat(1000000))
// Result: Memory exhaustion, server crash

/**
 * VULNERABILITY #5: Unsafe File Upload Handling
 * Problem: No validation of file types, sizes, or content
 * Attack Vector: Malware upload, server compromise
 */
function handleFileUploadInsecure(file) {
    // DANGEROUS: No validation whatsoever
    const reader = new FileReader();
    reader.onload = function(e) {
        // Direct processing without checks
        document.body.innerHTML += e.target.result;
    };
    reader.readAsText(file);
}

// Attack scenario:
// Upload a .txt file containing: "<script>maliciousCode()</script>"
// Result: XSS execution when file content is processed

/**
 * VULNERABILITY #6: Regex Denial of Service (ReDoS)
 * Problem: Inefficient regex patterns vulnerable to catastrophic backtracking
 * Attack Vector: DoS through CPU exhaustion
 */
function validateInputWithBadRegexInsecure(input) {
    // DANGEROUS: Vulnerable to ReDoS
    const vulnRegex = /^(a+)+$/;
    return vulnRegex.test(input);
}

// Attack example:
// validateInputWithBadRegexInsecure("aaaaaaaaaaaaaaaaaaaaaaaaaaX")
// Result: CPU exhaustion due to catastrophic backtracking

/**
 * VULNERABILITY #7: SQL Injection through String Concatenation
 * Problem: Building queries with direct string concatenation
 * Attack Vector: SQL injection, data breach
 */
function findUserInsecure(username) {
    // DANGEROUS: Direct string concatenation
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    // This would be executed directly in a real scenario
    return query;
}

// Attack example:
// findUserInsecure("admin'; DROP TABLE users; --")
// Result: SQL injection - potential database destruction

/**
 * VULNERABILITY #8: Unsafe JSON Parsing
 * Problem: Parsing JSON without validation or error handling
 * Attack Vector: Code injection, DoS, information disclosure
 */
function processJSONInsecure(jsonString) {
    // DANGEROUS: Direct parsing without validation
    const data = eval(`(${jsonString})`); // Double dangerous - eval usage
    return data.userInfo;
}

// Attack example:
// processJSONInsecure("({userInfo: alert('XSS'), malicious: function(){/* payload */}()})")
// Result: Code execution through eval

/**
 * VULNERABILITY #9: Unsafe URL Handling
 * Problem: No validation of URLs before use
 * Attack Vector: Open redirect, SSRF, XSS through javascript: URLs
 */
function redirectUserInsecure(url) {
    // DANGEROUS: No URL validation
    window.location.href = url;
}

// Attack examples:
// redirectUserInsecure("javascript:alert('XSS')")  // XSS
// redirectUserInsecure("http://evil.com")          // Open redirect
// redirectUserInsecure("file:///etc/passwd")       // Local file access attempt

/**
 * VULNERABILITY #10: Insufficient Error Handling
 * Problem: Exposing system information through error messages
 * Attack Vector: Information disclosure, system reconnaissance
 */
function processDataInsecure(input) {
    try {
        // Some processing that might fail
        return JSON.parse(input);
    } catch (error) {
        // DANGEROUS: Exposing system information
        return {
            error: error.message,
            stack: error.stack,
            systemInfo: navigator.userAgent,
            timestamp: new Date()
        };
    }
}

// Problem: Attackers can trigger errors to gather system information
// for more targeted attacks

/**
 * DEMONSTRATION FUNCTION - Shows multiple vulnerabilities together
 * WARNING: This represents real-world vulnerable code patterns
 */
function vulnerableUserProfileInsecure(userData) {
    // Multiple vulnerabilities in one function
    const profile = document.createElement('div');
    
    // Vulnerability 1: XSS through innerHTML
    profile.innerHTML = `<h2>${userData.name}</h2>`;
    
    // Vulnerability 2: No input validation
    if (userData.website) {
        // Vulnerability 3: Unsafe URL handling
        profile.innerHTML += `<a href="${userData.website}">Website</a>`;
    }
    
    // Vulnerability 4: Information disclosure
    try {
        const preferences = JSON.parse(userData.preferences);
        profile.innerHTML += `<p>Preferences: ${preferences}</p>`;
    } catch (e) {
        // Vulnerability 5: Error information leakage
        profile.innerHTML += `<p>Error: ${e.message}</p>`;
    }
    
    return profile;
}

// This single function contains at least 5 different attack vectors

/**
 * EDUCATIONAL NOTES:
 * 
 * 1. XSS (Cross-Site Scripting): Occurs when user input is rendered 
 *    as HTML without proper sanitization
 * 
 * 2. Injection Attacks: SQL, NoSQL, LDAP, etc. - when user input
 *    is used to construct queries without proper escaping
 * 
 * 3. DoS (Denial of Service): Through resource exhaustion via
 *    large inputs, complex regex, or memory-intensive operations
 * 
 * 4. Information Disclosure: Exposing system details through
 *    error messages or unfiltered responses
 * 
 * 5. Open Redirect: Allowing attackers to redirect users to
 *    malicious sites using your trusted domain
 * 
 * MITIGATION: See secure.js for proper implementations that
 * prevent all these vulnerabilities.
 */

// Export for educational analysis (DO NOT USE IN PRODUCTION)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        // Mark as insecure for tooling
        INSECURE_EXAMPLES: true,
        processUserDataInsecure,
        validateEmailInsecure,
        displayUserContentInsecure,
        processLongTextInsecure,
        handleFileUploadInsecure,
        validateInputWithBadRegexInsecure,
        findUserInsecure,
        processJSONInsecure,
        redirectUserInsecure,
        processDataInsecure,
        vulnerableUserProfileInsecure
    };
}