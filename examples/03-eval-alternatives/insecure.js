/**
 * INSECURE eval() Usage - DO NOT USE IN PRODUCTION
 * 
 * Demonstrates dangerous eval() patterns for educational purposes.
 */

/**
 * ❌ VULNERABLE: Direct eval of user input
 */
function unsafeEval(userInput) {
    return eval(userInput);
    // Allows arbitrary code execution
}

/**
 * ❌ VULNERABLE: setTimeout with string
 */
function unsafeTimeout(code, delay) {
    return setTimeout(code, delay);
    // Equivalent to eval()
}

/**
 * ❌ VULNERABLE: Function constructor with user input
 */
function unsafeFunctionCreate(userCode) {
    return new Function(userCode)();
    // No sandboxing or validation
}

/**
 * ❌ VULNERABLE: Template with eval
 */
function unsafeTemplate(template, data) {
    return template.replace(/\$\{(.+?)\}/g, (match, expr) => {
        return eval(expr); // Executes arbitrary code
    });
}

/**
 * ❌ VULNERABLE: Dynamic property access
 */
function unsafePropertyAccess(obj, path) {
    return eval(`obj.${path}`);
    // Allows prototype pollution
}

/**
 * ❌ VULNERABLE: Expression evaluator
 */
function unsafeCalculator(expression) {
    // No validation
    return eval(expression);
}

/**
 * ❌ VULNERABLE: Config parser with eval
 */
function unsafeConfigParse(configString) {
    // Executes code in config
    return eval(`(${configString})`);
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        unsafeEval,
        unsafeTimeout,
        unsafeFunctionCreate,
        unsafeTemplate,
        unsafePropertyAccess,
        unsafeCalculator,
        unsafeConfigParse
    };
}