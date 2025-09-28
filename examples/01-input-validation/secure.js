/**
 * Secure Input Validation Patterns
 * 
 * This module provides secure input validation methods that prevent
 * common injection attacks while maintaining high performance.
 * 
 * Original research by Nexus Studio - nexusstudio100@gmail.com
 */

/**
 * Validates and sanitizes user input according to specified rules
 * @param {any} input - The input to validate
 * @param {Object} rules - Validation rules
 * @param {string} rules.type - Expected type (string, number, email, etc.)
 * @param {number} rules.maxLength - Maximum allowed length
 * @param {RegExp} rules.allowedChars - Regex for allowed characters
 * @param {boolean} rules.required - Whether the field is required
 * @returns {Object} Validation result with isValid boolean and sanitized value
 */
function validateInput(input, rules = {}) {
    const result = {
        isValid: false,
        value: null,
        errors: []
    };

    // Handle required fields
    if (rules.required && (input === null || input === undefined || input === '')) {
        result.errors.push('Field is required');
        return result;
    }

    // Allow empty non-required fields
    if (!rules.required && (input === null || input === undefined || input === '')) {
        result.isValid = true;
        result.value = '';
        return result;
    }

    // Type validation
    switch (rules.type) {
        case 'string':
            if (typeof input !== 'string') {
                result.errors.push('Expected string type');
                return result;
            }
            break;
        
        case 'number':
            const num = Number(input);
            if (isNaN(num) || !isFinite(num)) {
                result.errors.push('Expected valid number');
                return result;
            }
            input = num;
            break;
        
        case 'email':
            if (typeof input !== 'string') {
                result.errors.push('Email must be a string');
                return result;
            }
            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!emailRegex.test(input)) {
                result.errors.push('Invalid email format');
                return result;
            }
            break;
        
        case 'url':
            if (typeof input !== 'string') {
                result.errors.push('URL must be a string');
                return result;
            }
            try {
                const url = new URL(input);
                // Only allow http and https
                if (!['http:', 'https:'].includes(url.protocol)) {
                    result.errors.push('URL must use HTTP or HTTPS protocol');
                    return result;
                }
                input = url.href;
            } catch (e) {
                result.errors.push('Invalid URL format');
                return result;
            }
            break;
    }

    // Length validation
    if (rules.maxLength && typeof input === 'string' && input.length > rules.maxLength) {
        result.errors.push(`Input exceeds maximum length of ${rules.maxLength}`);
        return result;
    }

    // Character validation
    if (rules.allowedChars && typeof input === 'string' && !rules.allowedChars.test(input)) {
        result.errors.push('Input contains disallowed characters');
        return result;
    }

    // If we get here, input is valid
    result.isValid = true;
    result.value = input;
    return result;
}

/**
 * Sanitizes HTML content to prevent XSS attacks
 * @param {string} html - HTML content to sanitize
 * @returns {string} Sanitized HTML content
 */
function sanitizeHTML(html) {
    if (typeof html !== 'string') {
        return '';
    }

    // Remove script tags and their content
    html = html.replace(/<script[^>]*>.*?<\/script>/gi, '');
    
    // Remove iframe tags and their content
    html = html.replace(/<iframe[^>]*>.*?<\/iframe>/gi, '');
    
    // Remove on* event handlers
    html = html.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
    html = html.replace(/\s*on\w+\s*=\s*[^>\s]+/gi, '');
    
    // Remove javascript: protocol
    html = html.replace(/javascript:/gi, '');
    
    // Remove data: URLs (can contain embedded scripts)
    html = html.replace(/data:\s*[^;]*;[^,]*,/gi, '');
    
    // Escape remaining HTML entities for safety
    return html
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

/**
 * Safe alternative to innerHTML for dynamic content
 * @param {HTMLElement} element - Target element
 * @param {string} content - Content to insert
 */
function safeInsertHTML(element, content) {
    if (!(element instanceof HTMLElement)) {
        throw new Error('First argument must be an HTML element');
    }
    
    const sanitized = sanitizeHTML(content);
    element.textContent = sanitized;
}

/**
 * Validates file uploads securely
 * @param {File} file - File object to validate
 * @param {Object} options - Validation options
 * @param {Array} options.allowedTypes - Allowed MIME types
 * @param {number} options.maxSize - Maximum file size in bytes
 * @returns {Object} Validation result
 */
function validateFileUpload(file, options = {}) {
    const result = {
        isValid: false,
        errors: []
    };

    if (!(file instanceof File)) {
        result.errors.push('Invalid file object');
        return result;
    }

    // Check file size
    if (options.maxSize && file.size > options.maxSize) {
        result.errors.push(`File size exceeds maximum of ${options.maxSize} bytes`);
        return result;
    }

    // Check file type
    if (options.allowedTypes && !options.allowedTypes.includes(file.type)) {
        result.errors.push('File type not allowed');
        return result;
    }

    // Additional security: Check file extension matches MIME type
    const extension = file.name.split('.').pop().toLowerCase();
    const mimeTypeMap = {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'pdf': 'application/pdf',
        'txt': 'text/plain'
    };

    if (mimeTypeMap[extension] && mimeTypeMap[extension] !== file.type) {
        result.errors.push('File extension does not match content type');
        return result;
    }

    result.isValid = true;
    return result;
}

/**
 * Secure parameter parsing from URL or form data
 * @param {string|URLSearchParams|FormData} source - Source of parameters
 * @param {Object} schema - Expected parameter schema
 * @returns {Object} Parsed and validated parameters
 */
function parseSecureParameters(source, schema = {}) {
    const result = {
        isValid: true,
        data: {},
        errors: []
    };

    let params;
    
    if (typeof source === 'string') {
        // Parse URL query string
        params = new URLSearchParams(source);
    } else if (source instanceof URLSearchParams || source instanceof FormData) {
        params = source;
    } else {
        result.isValid = false;
        result.errors.push('Invalid parameter source');
        return result;
    }

    // Validate each parameter according to schema
    for (const [key, rules] of Object.entries(schema)) {
        const value = params.get(key);
        const validation = validateInput(value, rules);
        
        if (!validation.isValid) {
            result.isValid = false;
            result.errors.push(`${key}: ${validation.errors.join(', ')}`);
        } else {
            result.data[key] = validation.value;
        }
    }

    return result;
}

// Export for Node.js environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        validateInput,
        sanitizeHTML,
        safeInsertHTML,
        validateFileUpload,
        parseSecureParameters
    };
}

// Export for browser environments
if (typeof window !== 'undefined') {
    window.SecureValidation = {
        validateInput,
        sanitizeHTML,
        safeInsertHTML,
        validateFileUpload,
        parseSecureParameters
    };
}