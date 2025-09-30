/**
 * INSECURE XSS Prevention Patterns - DO NOT USE IN PRODUCTION
 * 
 * This file demonstrates common XSS vulnerabilities for educational purposes.
 * These patterns are deliberately insecure to show what NOT to do.
 */

/**
 * ❌ VULNERABLE: Directly setting innerHTML without sanitization
 */
function unsafeSetHTML(element, html) {
    // Allows script injection
    element.innerHTML = html;
}

/**
 * ❌ VULNERABLE: Inadequate HTML escaping
 */
function inadequateEscape(text) {
    // Only escapes < and >, missing many attack vectors
    return text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * ❌ VULNERABLE: Blacklist-based sanitization (easily bypassed)
 */
function blacklistSanitize(html) {
    // Blacklists are incomplete and bypassable
    return html
        .replace(/<script>/gi, '')  // Bypassed by: <SCRIPT>, <scr<script>ipt>
        .replace(/javascript:/gi, ''); // Bypassed by: java\0script:, jAvAsCrIpT:
}

/**
 * ❌ VULNERABLE: No URL validation
 */
function unsafeCreateLink(url, text) {
    return `<a href="${url}">${text}</a>`;
    // Allows: javascript:alert('XSS')
}

/**
 * ❌ VULNERABLE: Direct eval of user content
 */
function unsafeRenderTemplate(template, data) {
    // Uses eval-like behavior
    return template.replace(/\{\{(.+?)\}\}/g, (match, code) => {
        return eval(code); // EXTREMELY DANGEROUS
    });
}

/**
 * ❌ VULNERABLE: No event handler sanitization
 */
function unsafeCreateButton(label, onClick) {
    return `<button onclick="${onClick}">${label}</button>`;
    // Allows: alert('XSS')
}

/**
 * ❌ VULNERABLE: Unsafe JSON parsing
 */
function unsafeJSONParse(jsonString) {
    // No prototype pollution check
    return JSON.parse(jsonString);
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        unsafeSetHTML,
        inadequateEscape,
        blacklistSanitize,
        unsafeCreateLink,
        unsafeRenderTemplate,
        unsafeCreateButton,
        unsafeJSONParse
    };
}