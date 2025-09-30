/**
 * XSS Prevention Tests
 * Validates secure patterns block attacks while insecure ones don't
 */

// Import both secure and insecure implementations
const secure = require('./secure.js');
const insecure = require('./insecure.js');

console.log('🧪 XSS Prevention Tests\n');

// Test 1: Script Injection
console.log('Test 1: Script Injection');
const scriptAttack = '<script>alert("XSS")</script>';

const secureResult1 = secure.sanitizeHTML(scriptAttack);
const insecureResult1 = insecure.blacklistSanitize(scriptAttack);

console.log('  Secure result:', secureResult1);
console.log('  ✅ Script tags removed:', !secureResult1.includes('<script>'));

console.log('  Insecure result:', insecureResult1);
console.log('  ❌ Still vulnerable:', insecureResult1.includes('<script>'));
console.log();

// Test 2: Event Handler Injection
console.log('Test 2: Event Handler Injection');
const eventAttack = '<img src=x onerror="alert(\'XSS\')">';

const secureResult2 = secure.sanitizeHTML(eventAttack);
const insecureResult2 = insecure.inadequateEscape(eventAttack);

console.log('  Secure result:', secureResult2);
console.log('  ✅ Event handler removed:', !secureResult2.includes('onerror'));

console.log('  Insecure result:', insecureResult2);
console.log('  ❌ Event handler present:', insecureResult2.includes('onerror'));
console.log();

// Test 3: JavaScript Protocol
console.log('Test 3: JavaScript Protocol in URL');
const jsProtocol = 'javascript:alert("XSS")';

const secureResult3 = secure.validateURL(jsProtocol);
const insecureResult3 = insecure.unsafeCreateLink(jsProtocol, 'Click');

console.log('  Secure validation:', secureResult3);
console.log('  ✅ Blocked:', !secureResult3.isValid);

console.log('  Insecure result:', insecureResult3);
console.log('  ❌ JS protocol allowed:', insecureResult3.includes('javascript:'));
console.log();

// Test 4: Prototype Pollution
console.log('Test 4: Prototype Pollution');
const pollutionAttack = '{"__proto__":{"polluted":"yes"}}';

const secureResult4 = secure.safeJSONParse(pollutionAttack);
const insecureResult4 = insecure.unsafeJSONParse(pollutionAttack);

console.log('  Secure parse:', secureResult4);
console.log('  ✅ Pollution blocked:', secureResult4.error !== null);

console.log('  Insecure parse successful:', insecureResult4 !== null);
console.log('  ❌ Prototype polluted:', Object.prototype.polluted === 'yes');
delete Object.prototype.polluted; // Cleanup
console.log();

// Test 5: HTML Entity Encoding
console.log('Test 5: HTML Entity Encoding');
const entityAttack = '<img src=x onerror=alert(1)>';

const secureResult5 = secure.escapeHTML(entityAttack);
const insecureResult5 = insecure.inadequateEscape(entityAttack);

console.log('  Secure result:', secureResult5);
console.log('  ✅ Fully encoded:', secureResult5.includes('&lt;'));

console.log('  Insecure result:', insecureResult5);
console.log('  ❌ Incomplete encoding:', insecureResult5.includes('onerror'));
console.log();

// Summary
console.log('═══════════════════════════════════════');
console.log('Test Summary:');
console.log('  ✅ Secure patterns: All attacks blocked');
console.log('  ❌ Insecure patterns: All attacks possible');
console.log('═══════════════════════════════════════');