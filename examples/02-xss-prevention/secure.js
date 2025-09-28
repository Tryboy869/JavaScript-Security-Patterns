/**
 * XSS Prevention Security Patterns
 * 
 * This module provides comprehensive XSS (Cross-Site Scripting) prevention
 * techniques that block malicious script injection while preserving functionality.
 * 
 * Original research by Nexus Studio - nexusstudio100@gmail.com
 */

/**
 * Comprehensive HTML sanitizer that removes XSS vectors
 * @param {string} html - HTML content to sanitize
 * @param {Object} options - Sanitization options
 * @returns {string} Sanitized HTML safe for DOM insertion
 */
function sanitizeHTML(html, options = {}) {
    if (typeof html !== 'string') {
        return '';
    }

    const {
        allowBasicFormatting = false,
        allowLinks = false,
        allowImages = false,
        maxLength = 10000
    } = options;

    // Truncate excessively long input to prevent DoS
    if (html.length > maxLength) {
        html = html.substring(0, maxLength);
    }

    // Remove all script tags and content
    html = html.replace(/<script[^>]*>.*?<\/script>/gis, '');
    
    // Remove all style tags (can contain expression() attacks)
    html = html.replace(/<style[^>]*>.*?<\/style>/gis, '');
    
    // Remove all iframe, object, embed tags
    html = html.replace(/<(iframe|object|embed|applet|meta)[^>]*>.*?<\/\1>/gis, '');
    html = html.replace(/<(iframe|object|embed|applet|meta)[^>]*\/?>/gi, '');
    
    // Remove all event handlers (on* attributes)
    html = html.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
    html = html.replace(/\s*on\w+\s*=\s*[^>\s]+/gi, '');
    
    // Remove javascript: and data: protocols
    html = html.replace(/javascript\s*:/gi, 'blocked:');
    html = html.replace(/data\s*:/gi, 'blocked:');
    html = html.replace(/vbscript\s*:/gi, 'blocked:');
    
    // Remove expression() CSS attacks
    html = html.replace(/expression\s*\([^)]*\)/gi, 'blocked');
    
    // Remove import and @import CSS attacks  
    html = html.replace(/@import/gi, 'blocked');
    
    // Handle conditional formatting based on options
    if (!allowBasicFormatting) {
        // Remove all HTML tags if formatting not allowed
        html = html.replace(/<[^>]*>/g, '');
    } else {
        // Keep only safe formatting tags
        const safeTags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br', 'span', 'div'];
        html = html.replace(/<(\/?)([\w]+)[^>]*>/gi, (match, slash, tag) => {
            if (safeTags.includes(tag.toLowerCase())) {
                return `<${slash}${tag.toLowerCase()}>`;
            }
            return '';
        });
    }
    
    if (!allowLinks) {
        html = html.replace(/<a[^>]*>.*?<\/a>/gi, '');
    } else {
        // Sanitize link attributes
        html = html.replace(/<a\s+([^>]*?)>/gi, (match, attrs) => {
            // Only allow href and title attributes
            const hrefMatch = attrs.match(/href\s*=\s*["']([^"']+)["']/i);
            const titleMatch = attrs.match(/title\s*=\s*["']([^"']+)["']/i);
            
            let sanitizedAttrs = '';
            if (hrefMatch) {
                const href = hrefMatch[1];
                // Only allow http, https, and mailto protocols
                if (/^(https?:|mailto:)/i.test(href)) {
                    sanitizedAttrs += ` href="${encodeURI(href)}"`;
                }
            }
            if (titleMatch) {
                sanitizedAttrs += ` title="${escapeHTML(titleMatch[1])}"`;
            }
            
            return `<a${sanitizedAttrs}>`;
        });
    }
    
    if (!allowImages) {
        html = html.replace(/<img[^>]*>/gi, '');
    } else {
        // Sanitize image attributes
        html = html.replace(/<img\s+([^>]*?)>/gi, (match, attrs) => {
            const srcMatch = attrs.match(/src\s*=\s*["']([^"']+)["']/i);
            const altMatch = attrs.match(/alt\s*=\s*["']([^"']+)["']/i);
            
            let sanitizedAttrs = '';
            if (srcMatch) {
                const src = srcMatch[1];
                // Only allow http, https, and data image protocols
                if (/^(https?:|data:image\/)/i.test(src)) {
                    sanitizedAttrs += ` src="${encodeURI(src)}"`;
                }
            }
            if (altMatch) {
                sanitizedAttrs += ` alt="${escapeHTML(altMatch[1])}"`;
            }
            
            return `<img${sanitizedAttrs}>`;
        });
    }
    
    // Final entity encoding for any remaining special characters
    return escapeHTML(html);
}

/**
 * Escapes HTML entities to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} HTML entity encoded text
 */
function escapeHTML(text) {
    if (typeof text !== 'string') {
        return '';
    }
    
    const entityMap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
        '`': '&#x60;',
        '=': '&#x3D;'
    };
    
    return text.replace(/[&<>"'`=\/]/g, char => entityMap[char]);
}

/**
 * Safely sets text content without HTML interpretation
 * @param {HTMLElement} element - Target element
 * @param {string} content - Content to set
 */
function safeSetText(element, content) {
    if (!(element instanceof Element)) {
        throw new Error('First argument must be a DOM element');
    }
    
    // Use textContent to avoid HTML parsing
    element.textContent = String(content || '');
}

/**
 * Safely sets HTML content after sanitization
 * @param {HTMLElement} element - Target element  
 * @param {string} html - HTML content to set
 * @param {Object} options - Sanitization options
 */
function safeSetHTML(element, html, options = {}) {
    if (!(element instanceof Element)) {
        throw new Error('First argument must be a DOM element');
    }
    
    const sanitized = sanitizeHTML(html, options);
    element.innerHTML = sanitized;
}

/**
 * Creates a DocumentFragment with sanitized content
 * @param {string} html - HTML to parse safely
 * @param {Object} options - Sanitization options
 * @returns {DocumentFragment} Safe document fragment
 */
function createSafeFragment(html, options = {}) {
    const sanitized = sanitizeHTML(html, options);
    const template = document.createElement('template');
    template.innerHTML = sanitized;
    return template.content.cloneNode(true);
}

/**
 * Safe URL validator that prevents XSS through URL schemes
 * @param {string} url - URL to validate
 * @param {Array} allowedProtocols - Allowed URL protocols
 * @returns {Object} Validation result
 */
function validateURL(url, allowedProtocols = ['http:', 'https:', 'mailto:']) {
    const result = {
        isValid: false,
        sanitizedURL: '',
        errors: []
    };
    
    if (typeof url !== 'string') {
        result.errors.push('URL must be a string');
        return result;
    }
    
    // Remove whitespace that could hide malicious protocols
    url = url.trim();
    
    // Check for obviously malicious patterns
    const dangerousPatterns = [
        /javascript:/i,
        /vbscript:/i,
        /data:/i,
        /file:/i,
        /ftp:/i
    ];
    
    for (const pattern of dangerousPatterns) {
        if (pattern.test(url)) {
            result.errors.push('Dangerous URL protocol detected');
            return result;
        }
    }
    
    try {
        const parsedURL = new URL(url);
        
        if (!allowedProtocols.includes(parsedURL.protocol)) {
            result.errors.push(`Protocol ${parsedURL.protocol} not allowed`);
            return result;
        }
        
        // Additional security checks
        if (parsedURL.hostname === 'localhost' || 
            parsedURL.hostname.startsWith('127.') ||
            parsedURL.hostname.startsWith('192.168.') ||
            parsedURL.hostname.startsWith('10.')) {
            result.errors.push('Private/local URLs not allowed');
            return result;
        }
        
        result.isValid = true;
        result.sanitizedURL = parsedURL.href;
        
    } catch (error) {
        result.errors.push('Invalid URL format');
    }
    
    return result;
}

/**
 * Content Security Policy helper functions
 */
const CSP = {
    /**
     * Generates a secure CSP header value
     * @param {Object} options - CSP configuration options
     * @returns {string} CSP header value
     */
    generate(options = {}) {
        const {
            allowInlineStyles = false,
            allowInlineScripts = false,
            allowEval = false,
            trustedDomains = []
        } = options;
        
        let csp = "default-src 'self'";
        
        // Script source policy
        let scriptSrc = "'self'";
        if (allowInlineScripts) {
            scriptSrc += " 'unsafe-inline'";
        }
        if (allowEval) {
            scriptSrc += " 'unsafe-eval'";
        }
        trustedDomains.forEach(domain => {
            scriptSrc += ` ${domain}`;
        });
        csp += `; script-src ${scriptSrc}`;
        
        // Style source policy
        let styleSrc = "'self'";
        if (allowInlineStyles) {
            styleSrc += " 'unsafe-inline'";
        }
        csp += `; style-src ${styleSrc}`;
        
        // Additional security headers
        csp += "; object-src 'none'";
        csp += "; base-uri 'self'";
        csp += "; form-action 'self'";
        csp += "; frame-ancestors 'none'";
        
        return csp;
    },
    
    /**
     * Sets CSP header on response (Node.js)
     * @param {Object} res - Express response object
     * @param {Object} options - CSP options
     */
    setHeader(res, options = {}) {
        const cspValue = this.generate(options);
        res.setHeader('Content-Security-Policy', cspValue);
    }
};

/**
 * Safe JSON parsing that prevents prototype pollution
 * @param {string} jsonString - JSON string to parse
 * @returns {Object} Parsing result
 */
function safeJSONParse(jsonString) {
    const result = {
        success: false,
        data: null,
        error: null
    };
    
    if (typeof jsonString !== 'string') {
        result.error = 'Input must be a string';
        return result;
    }
    
    // Check for prototype pollution attempts
    if (jsonString.includes('__proto__') || 
        jsonString.includes('constructor') ||
        jsonString.includes('prototype')) {
        result.error = 'Potentially dangerous JSON content detected';
        return result;
    }
    
    try {
        const parsed = JSON.parse(jsonString);
        
        // Additional security: remove any prototype pollution attempts
        const cleaned = removePrototypePollution(parsed);
        
        result.success = true;
        result.data = cleaned;
        
    } catch (error) {
        result.error = 'Invalid JSON format';
    }
    
    return result;
}

/**
 * Recursively removes prototype pollution attempts from objects
 * @param {any} obj - Object to clean
 * @returns {any} Cleaned object
 */
function removePrototypePollution(obj) {
    if (obj === null || typeof obj !== 'object') {
        return obj;
    }
    
    if (Array.isArray(obj)) {
        return obj.map(removePrototypePollution);
    }
    
    const cleaned = {};
    for (const key in obj) {
        if (key !== '__proto__' && key !== 'constructor' && key !== 'prototype') {
            if (obj.hasOwnProperty(key)) {
                cleaned[key] = removePrototypePollution(obj[key]);
            }
        }
    }
    
    return cleaned;
}

// Export for Node.js environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        sanitizeHTML,
        escapeHTML,
        safeSetText,
        safeSetHTML,
        createSafeFragment,
        validateURL,
        CSP,
        safeJSONParse,
        removePrototypePollution
    };
}

// Export for browser environments
if (typeof window !== 'undefined') {
    window.XSSPrevention = {
        sanitizeHTML,
        escapeHTML,
        safeSetText,
        safeSetHTML,
        createSafeFragment,
        validateURL,
        CSP,
        safeJSONParse,
        removePrototypePollution
    };
}