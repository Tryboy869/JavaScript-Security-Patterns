/**
 * Safe eval() Alternatives - Secure Dynamic Code Execution
 * 
 * This module provides secure alternatives to eval() that prevent code injection
 * while enabling safe dynamic expression evaluation and code execution.
 * 
 * Original research by Nexus Studio - nexusstudio100@gmail.com
 */

/**
 * Safe expression evaluator for mathematical expressions
 * @param {string} expression - Mathematical expression to evaluate
 * @param {Object} context - Allowed variables and functions
 * @returns {Object} Evaluation result
 */
function secureEval(expression, context = {}) {
    const result = {
        success: false,
        value: null,
        error: null
    };
    
    if (typeof expression !== 'string') {
        result.error = 'Expression must be a string';
        return result;
    }
    
    // Remove whitespace for analysis
    const cleanExpression = expression.replace(/\s+/g, '');
    
    // Validate expression contains only allowed characters
    const allowedPattern = /^[\d\w\s+\-*/.(),%]+$/;
    if (!allowedPattern.test(expression)) {
        result.error = 'Expression contains disallowed characters';
        return result;
    }
    
    // Block dangerous keywords
    const dangerousKeywords = [
        'eval', 'Function', 'constructor', '__proto__', 'prototype',
        'import', 'require', 'process', 'global', 'window', 'document',
        'alert', 'confirm', 'prompt', 'console', 'setTimeout', 'setInterval'
    ];
    
    for (const keyword of dangerousKeywords) {
        if (expression.includes(keyword)) {
            result.error = `Dangerous keyword detected: ${keyword}`;
            return result;
        }
    }
    
    // Create safe context with Math functions
    const safeContext = {
        Math: Math,
        parseInt: parseInt,
        parseFloat: parseFloat,
        Number: Number,
        ...context
    };
    
    try {
        // Use Function constructor with strict mode for better security
        const func = new Function(
            ...Object.keys(safeContext),
            `"use strict"; return (${expression});`
        );
        
        const value = func(...Object.values(safeContext));
        
        // Validate result is a safe type
        if (typeof value === 'function') {
            result.error = 'Expression cannot evaluate to a function';
            return result;
        }
        
        result.success = true;
        result.value = value;
        
    } catch (error) {
        result.error = 'Expression evaluation failed';
    }
    
    return result;
}

/**
 * Safe template processor that prevents code injection
 * @param {string} template - Template string with ${variable} placeholders
 * @param {Object} data - Data object for variable substitution
 * @returns {string} Processed template
 */
function safeTemplate(template, data = {}) {
    if (typeof template !== 'string') {
        return '';
    }
    
    // Find all template variables
    const variablePattern = /\$\{([^}]+)\}/g;
    
    return template.replace(variablePattern, (match, variableName) => {
        const trimmedName = variableName.trim();
        
        // Only allow simple variable names (no expressions)
        if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(trimmedName)) {
            return '[Invalid Variable]';
        }
        
        // Get nested property safely
        const value = getNestedProperty(data, trimmedName);
        
        // Escape HTML entities in the result
        return escapeHTML(String(value ?? ''));
    });
}

/**
 * Safely gets nested object properties without eval
 * @param {Object} obj - Object to traverse
 * @param {string} path - Dot-notation property path
 * @returns {any} Property value or undefined
 */
function getNestedProperty(obj, path) {
    if (!obj || typeof path !== 'string') {
        return undefined;
    }
    
    const parts = path.split('.');
    let current = obj;
    
    for (const part of parts) {
        // Validate property name
        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(part)) {
            return undefined;
        }
        
        if (current && typeof current === 'object' && part in current) {
            current = current[part];
        } else {
            return undefined;
        }
    }
    
    return current;
}

/**
 * Safe JSON path evaluator
 * @param {Object} data - Data object to query
 * @param {string} path - JSON path expression
 * @returns {Object} Query result
 */
function safeJSONPath(data, path) {
    const result = {
        success: false,
        value: null,
        error: null
    };
    
    if (!data || typeof data !== 'object') {
        result.error = 'Data must be an object';
        return result;
    }
    
    if (typeof path !== 'string') {
        result.error = 'Path must be a string';
        return result;
    }
    
    // Simple JSON path implementation (safer than eval-based solutions)
    try {
        // Remove leading $ if present
        const cleanPath = path.replace(/^\$\.?/, '');
        
        if (cleanPath === '') {
            result.success = true;
            result.value = data;
            return result;
        }
        
        // Split path and traverse safely
        const parts = cleanPath.split('.');
        let current = data;
        
        for (const part of parts) {
            // Handle array indices
            if (/^\d+$/.test(part)) {
                const index = parseInt(part, 10);
                if (Array.isArray(current) && index < current.length) {
                    current = current[index];
                } else {
                    result.error = `Array index ${index} out of bounds`;
                    return result;
                }
            } 
            // Handle object properties
            else if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(part)) {
                if (current && typeof current === 'object' && part in current) {
                    current = current[part];
                } else {
                    result.error = `Property '${part}' not found`;
                    return result;
                }
            } 
            else {
                result.error = `Invalid path component: ${part}`;
                return result;
            }
        }
        
        result.success = true;
        result.value = current;
        
    } catch (error) {
        result.error = 'Path evaluation failed';
    }
    
    return result;
}

/**
 * Safe calculator for user-provided mathematical expressions
 * @param {string} expression - Mathematical expression
 * @returns {Object} Calculation result
 */
function safeCalculator(expression) {
    if (typeof expression !== 'string') {
        return { error: 'Expression must be a string', result: null };
    }
    
    // More restrictive pattern for calculator
    const calculatorPattern = /^[\d\s+\-*/().]+$/;
    if (!calculatorPattern.test(expression)) {
        return { error: 'Invalid mathematical expression', result: null };
    }
    
    // Check for balanced parentheses
    let parenCount = 0;
    for (const char of expression) {
        if (char === '(') parenCount++;
        if (char === ')') parenCount--;
        if (parenCount < 0) {
            return { error: 'Unbalanced parentheses', result: null };
        }
    }
    
    if (parenCount !== 0) {
        return { error: 'Unbalanced parentheses', result: null };
    }
    
    // Check for division by zero patterns
    if (/\/\s*0(?!\d)/.test(expression)) {
        return { error: 'Division by zero', result: null };
    }
    
    try {
        const func = new Function(`"use strict"; return (${expression});`);
        const result = func();
        
        if (!Number.isFinite(result)) {
            return { error: 'Result is not a finite number', result: null };
        }
        
        return { error: null, result: result };
        
    } catch (error) {
        return { error: 'Calculation failed', result: null };
    }
}

/**
 * Safe function executor with sandboxing
 * @param {string} functionBody - Function body to execute
 * @param {Object} allowedContext - Whitelisted context objects
 * @param {Array} args - Arguments to pass to the function
 * @returns {Object} Execution result
 */
function safeFunctionExecutor(functionBody, allowedContext = {}, args = []) {
    const result = {
        success: false,
        value: null,
        error: null
    };
    
    if (typeof functionBody !== 'string') {
        result.error = 'Function body must be a string';
        return result;
    }
    
    // Block dangerous patterns
    const dangerousPatterns = [
        /eval\s*\(/i,
        /Function\s*\(/i,
        /constructor/i,
        /prototype/i,
        /__proto__/i,
        /import\s+/i,
        /require\s*\(/i,
        /process\./i,
        /global\./i,
        /window\./i,
        /document\./i
    ];
    
    for (const pattern of dangerousPatterns) {
        if (pattern.test(functionBody)) {
            result.error = 'Function contains dangerous patterns';
            return result;
        }
    }
    
    try {
        // Create function with strict mode and limited context
        const contextKeys = Object.keys(allowedContext);
        const contextValues = Object.values(allowedContext);
        
        const func = new Function(
            ...contextKeys,
            'args',
            `"use strict"; ${functionBody}`
        );
        
        const value = func(...contextValues, args);
        
        result.success = true;
        result.value = value;
        
    } catch (error) {
        result.error = `Execution failed: ${error.message}`;
    }
    
    return result;
}

/**
 * Escapes HTML entities
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHTML(text) {
    const entityMap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;'
    };
    
    return String(text).replace(/[&<>"'\/]/g, char => entityMap[char]);
}

/**
 * Safe property accessor that prevents prototype pollution
 * @param {Object} obj - Object to access
 * @param {string} property - Property name
 * @returns {any} Property value or undefined
 */
function safePropertyAccess(obj, property) {
    if (!obj || typeof obj !== 'object') {
        return undefined;
    }
    
    // Block dangerous property names
    if (property === '__proto__' || 
        property === 'constructor' || 
        property === 'prototype') {
        return undefined;
    }
    
    // Only access own properties
    if (Object.prototype.hasOwnProperty.call(obj, property)) {
        return obj[property];
    }
    
    return undefined;
}

/**
 * Creates a sandboxed execution environment
 * @param {Object} whitelist - Whitelisted objects and functions
 * @returns {Object} Sandboxed environment
 */
function createSandbox(whitelist = {}) {
    const sandbox = {
        // Safe math operations
        Math: Math,
        Number: Number,
        parseInt: parseInt,
        parseFloat: parseFloat,
        isNaN: isNaN,
        isFinite: isFinite,
        
        // Safe string operations
        String: String,
        
        // Safe array operations
        Array: Array,
        
        // Add whitelisted items
        ...whitelist
    };
    
    // Freeze sandbox to prevent modifications
    return Object.freeze(sandbox);
}

/**
 * Validates and executes user-defined filter functions safely
 * @param {Array} data - Data array to filter
 * @param {string} filterExpression - Filter expression
 * @returns {Object} Filtered data result
 */
function safeFilter(data, filterExpression) {
    const result = {
        success: false,
        data: null,
        error: null
    };
    
    if (!Array.isArray(data)) {
        result.error = 'Data must be an array';
        return result;
    }
    
    if (typeof filterExpression !== 'string') {
        result.error = 'Filter expression must be a string';
        return result;
    }
    
    // Allow only simple comparison expressions
    const allowedPattern = /^[a-zA-Z_][a-zA-Z0-9_]*\s*[<>=!]+\s*[\d'"]+$/;
    if (!allowedPattern.test(filterExpression)) {
        result.error = 'Invalid filter expression format';
        return result;
    }
    
    try {
        // Parse expression into safe filter function
        const filterFunc = new Function('item', `"use strict"; return item.${filterExpression};`);
        
        const filtered = data.filter(item => {
            try {
                return filterFunc(item);
            } catch {
                return false;
            }
        });
        
        result.success = true;
        result.data = filtered;
        
    } catch (error) {
        result.error = 'Filter execution failed';
    }
    
    return result;
}

/**
 * Safe configuration parser for JSON/YAML-like config strings
 * @param {string} configString - Configuration string
 * @returns {Object} Parsed configuration
 */
function safeConfigParser(configString) {
    const result = {
        success: false,
        config: null,
        error: null
    };
    
    if (typeof configString !== 'string') {
        result.error = 'Config must be a string';
        return result;
    }
    
    try {
        // Remove comments
        const cleaned = configString
            .split('\n')
            .map(line => line.replace(/\/\/.*$/, '').trim())
            .filter(line => line.length > 0)
            .join('\n');
        
        // Parse as JSON
        const parsed = JSON.parse(cleaned);
        
        // Remove prototype pollution attempts
        const safe = removePrototypePollution(parsed);
        
        result.success = true;
        result.config = safe;
        
    } catch (error) {
        result.error = 'Configuration parsing failed';
    }
    
    return result;
}

/**
 * Removes prototype pollution attempts from parsed objects
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
        if (key !== '__proto__' && 
            key !== 'constructor' && 
            key !== 'prototype' &&
            Object.prototype.hasOwnProperty.call(obj, key)) {
            cleaned[key] = removePrototypePollution(obj[key]);
        }
    }
    
    return cleaned;
}

// Export for Node.js environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        secureEval,
        safeTemplate,
        getNestedProperty,
        safeJSONPath,
        safeCalculator,
        safeFunctionExecutor,
        escapeHTML,
        safePropertyAccess,
        createSandbox,
        safeFilter,
        safeConfigParser,
        removePrototypePollution
    };
}

// Export for browser environments
if (typeof window !== 'undefined') {
    window.SafeEval = {
        secureEval,
        safeTemplate,
        getNestedProperty,
        safeJSONPath,
        safeCalculator,
        safeFunctionExecutor,
        escapeHTML,
        safePropertyAccess,
        createSandbox,
        safeFilter,
        safeConfigParser,
        removePrototypePollution
    };
}