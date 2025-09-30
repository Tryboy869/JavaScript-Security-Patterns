/**
 * Test Suite for Input Validation Patterns
 * 
 * Nexus Studio - nexusstudio100@gmail.com
 */

const {
    validateInput,
    sanitizeHTML,
    safeInsertHTML,
    validateFileUpload,
    parseSecureParameters
} = require('./secure.js');

// Simple test framework
class TestRunner {
    constructor(name) {
        this.name = name;
        this.passed = 0;
        this.failed = 0;
        this.tests = [];
    }
    
    test(description, fn) {
        try {
            fn();
            this.passed++;
            console.log(`✅ ${description}`);
        } catch (error) {
            this.failed++;
            console.log(`❌ ${description}`);
            console.log(`   Error: ${error.message}`);
        }
    }
    
    assert(condition, message) {
        if (!condition) {
            throw new Error(message || 'Assertion failed');
        }
    }
    
    assertEqual(actual, expected, message) {
        if (actual !== expected) {
            throw new Error(message || `Expected ${expected}, got ${actual}`);
        }
    }
    
    report() {
        console.log(`\n${this.name} - Results:`);
        console.log(`Passed: ${this.passed}`);
        console.log(`Failed: ${this.failed}`);
        console.log(`Total: ${this.passed + this.failed}`);
        return this.failed === 0;
    }
}

// Test Suite
console.log('🧪 Starting Input Validation Test Suite\n');

const runner = new TestRunner('Input Validation');

// ============================================================================
// Basic Input Validation Tests
// ============================================================================

runner.test('validates string type correctly', () => {
    const result = validateInput('test string', { type: 'string', required: true });
    runner.assert(result.isValid === true);
    runner.assertEqual(result.value, 'test string');
});

runner.test('rejects non-string when string expected', () => {
    const result = validateInput(123, { type: 'string', required: true });
    runner.assert(result.isValid === false);
    runner.assert(result.errors.length > 0);
});

runner.test('validates number type correctly', () => {
    const result = validateInput('42', { type: 'number', required: true });
    runner.assert(result.isValid === true);
    runner.assertEqual(result.value, 42);
});

runner.test('rejects invalid number', () => {
    const result = validateInput('not a number', { type: 'number', required: true });
    runner.assert(result.isValid === false);
});

runner.test('validates email format correctly', () => {
    const result = validateInput('test@example.com', { type: 'email', required: true });
    runner.assert(result.isValid === true);
});

runner.test('rejects invalid email format', () => {
    const invalidEmails = [
        'notanemail',
        '@example.com',
        'test@',
        'test@@example.com',
        '<script>@evil.com'
    ];
    
    invalidEmails.forEach(email => {
        const result = validateInput(email, { type: 'email', required: true });
        runner.assert(result.isValid === false, `Should reject: ${email}`);
    });
});

runner.test('validates URL format correctly', () => {
    const result = validateInput('https://example.com', { type: 'url', required: true });
    runner.assert(result.isValid === true);
});

runner.test('rejects dangerous URL protocols', () => {
    const dangerousURLs = [
        'javascript:alert(1)',
        'data:text/html,<script>',
        'file:///etc/passwd',
        'ftp://example.com'
    ];
    
    dangerousURLs.forEach(url => {
        const result = validateInput(url, { type: 'url', required: true });
        runner.assert(result.isValid === false, `Should reject: ${url}`);
    });
});

runner.test('enforces maxLength correctly', () => {
    const result = validateInput('12345', { type: 'string', maxLength: 3, required: true });
    runner.assert(result.isValid === false);
    runner.assert(result.errors.some(e => e.includes('exceeds maximum length')));
});

runner.test('validates allowed characters', () => {
    const result = validateInput('abc123', {
        type: 'string',
        allowedChars: /^[a-z0-9]+$/,
        required: true
    });
    runner.assert(result.isValid === true);
    
    const invalid = validateInput('abc@123', {
        type: 'string',
        allowedChars: /^[a-z0-9]+$/,
        required: true
    });
    runner.assert(invalid.isValid === false);
});

runner.test('handles required field validation', () => {
    const result = validateInput('', { type: 'string', required: true });
    runner.assert(result.isValid === false);
    runner.assert(result.errors.some(e => e.includes('required')));
});

runner.test('allows empty non-required fields', () => {
    const result = validateInput('', { type: 'string', required: false });
    runner.assert(result.isValid === true);
    runner.assertEqual(result.value, '');
});

// ============================================================================
// HTML Sanitization Tests
// ============================================================================

runner.test('removes script tags', () => {
    const malicious = '<script>alert("XSS")</script>Hello';
    const sanitized = sanitizeHTML(malicious);
    runner.assert(!sanitized.includes('<script'));
    runner.assert(!sanitized.includes('alert'));
});

runner.test('removes event handlers', () => {
    const malicious = '<img src=x onerror="alert(1)">';
    const sanitized = sanitizeHTML(malicious);
    runner.assert(!sanitized.includes('onerror'));
    runner.assert(!sanitized.includes('alert'));
});

runner.test('removes javascript: protocol', () => {
    const malicious = '<a href="javascript:alert(1)">click</a>';
    const sanitized = sanitizeHTML(malicious);
    runner.assert(!sanitized.includes('javascript:'));
});

runner.test('removes iframe tags', () => {
    const malicious = '<iframe src="evil.com"></iframe>Hello';
    const sanitized = sanitizeHTML(malicious);
    runner.assert(!sanitized.includes('<iframe'));
    runner.assert(!sanitized.includes('evil.com'));
});

runner.test('escapes HTML entities', () => {
    const input = '<div>Test & "quotes"</div>';
    const sanitized = sanitizeHTML(input);
    runner.assert(sanitized.includes('&lt;'));
    runner.assert(sanitized.includes('&gt;'));
    runner.assert(sanitized.includes('&amp;'));
    runner.assert(sanitized.includes('&quot;'));
});

// FIX: Utiliser sanitizeHTML au lieu de validateInput
runner.test('handles mixed XSS vectors', () => {
    const attacks = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src=javascript:alert(1)>',
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">'
    ];
    
    attacks.forEach(attack => {
        const sanitized = sanitizeHTML(attack);
        runner.assert(!sanitized.includes('alert'), `Should sanitize: ${sanitized}`);
        runner.assert(!sanitized.includes('<script'), `Should remove script in: ${attack}`);
        runner.assert(!sanitized.includes('<iframe'), `Should remove iframe in: ${attack}`);
        runner.assert(!sanitized.includes('javascript'), `Should remove javascript protocol in: ${attack}`);
    });
});

// ============================================================================
// File Upload Validation Tests (mock File objects)
// ============================================================================

runner.test('validates file size', () => {
    const mockFile = {
        size: 6 * 1024 * 1024, // 6MB
        type: 'image/jpeg',
        name: 'test.jpg',
        constructor: { name: 'File' }
    };
    
    // Mock instanceof check
    mockFile[Symbol.toStringTag] = 'File';
    Object.setPrototypeOf(mockFile, File.prototype || {});
    
    const result = validateFileUpload(mockFile, {
        maxSize: 5 * 1024 * 1024, // 5MB limit
        allowedTypes: ['image/jpeg']
    });
    
    runner.assert(result.isValid === false);
    runner.assert(result.errors.some(e => e.includes('exceeds maximum')));
});

runner.test('validates file type', () => {
    const mockFile = {
        size: 1024,
        type: 'application/x-executable',
        name: 'malware.exe',
        constructor: { name: 'File' }
    };
    
    mockFile[Symbol.toStringTag] = 'File';
    Object.setPrototypeOf(mockFile, File.prototype || {});
    
    const result = validateFileUpload(mockFile, {
        maxSize: 10 * 1024 * 1024,
        allowedTypes: ['image/jpeg', 'image/png']
    });
    
    runner.assert(result.isValid === false);
    runner.assert(result.errors.some(e => e.includes('not allowed')));
});

// ============================================================================
// Parameter Parsing Tests
// ============================================================================

runner.test('parses URL parameters securely', () => {
    const params = 'name=John&age=30&email=john@example.com';
    const schema = {
        name: { type: 'string', maxLength: 100, required: true },
        age: { type: 'number', required: true },
        email: { type: 'email', required: true }
    };
    
    const result = parseSecureParameters(params, schema);
    runner.assert(result.isValid === true);
    runner.assertEqual(result.data.name, 'John');
    runner.assertEqual(result.data.age, 30);
    runner.assertEqual(result.data.email, 'john@example.com');
});

runner.test('rejects invalid parameters', () => {
    const params = 'name=<script>alert(1)</script>&age=invalid';
    const schema = {
        name: { type: 'string', maxLength: 50, allowedChars: /^[a-zA-Z]+$/, required: true },
        age: { type: 'number', required: true }
    };
    
    const result = parseSecureParameters(params, schema);
    runner.assert(result.isValid === false);
    runner.assert(result.errors.length > 0);
});

// ============================================================================
// Integration Tests
// ============================================================================

runner.test('complete user registration validation', () => {
    const formData = new URLSearchParams({
        username: 'testuser123',
        email: 'test@example.com',
        age: '25',
        bio: 'Hello world!'
    });
    
    const schema = {
        username: {
            type: 'string',
            maxLength: 30,
            allowedChars: /^[a-zA-Z0-9_-]+$/,
            required: true
        },
        email: {
            type: 'email',
            required: true
        },
        age: {
            type: 'number',
            required: true
        },
        bio: {
            type: 'string',
            maxLength: 500,
            required: false
        }
    };
    
    const result = parseSecureParameters(formData, schema);
    runner.assert(result.isValid === true);
    runner.assert(result.data.username === 'testuser123');
});

runner.test('blocks malicious registration attempt', () => {
    const maliciousData = new URLSearchParams({
        username: "admin' OR '1'='1",
        email: '<script>alert(1)</script>@evil.com',
        age: 'DROP TABLE users'
    });
    
    const schema = {
        username: {
            type: 'string',
            allowedChars: /^[a-zA-Z0-9_-]+$/,
            required: true
        },
        email: {
            type: 'email',
            required: true
        },
        age: {
            type: 'number',
            required: true
        }
    };
    
    const result = parseSecureParameters(maliciousData, schema);
    runner.assert(result.isValid === false);
});

// ============================================================================
// Security Edge Cases
// ============================================================================

runner.test('handles null and undefined safely', () => {
    runner.assert(validateInput(null, { required: false }).isValid === true);
    runner.assert(validateInput(undefined, { required: false }).isValid === true);
    runner.assert(validateInput(null, { required: true }).isValid === false);
});

runner.test('prevents type confusion attacks', () => {
    const attacks = [
        { value: [], type: 'string' },
        { value: {}, type: 'number' },
        { value: () => {}, type: 'string' }
    ];
    
    attacks.forEach(attack => {
        const result = validateInput(attack.value, { type: attack.type, required: true });
        runner.assert(result.isValid === false, `Should reject type: ${typeof attack.value}`);
    });
});

runner.test('handles very long inputs safely', () => {
    const longString = 'a'.repeat(100000);
    const result = validateInput(longString, {
        type: 'string',
        maxLength: 1000,
        required: true
    });
    runner.assert(result.isValid === false);
});

runner.test('sanitizes deeply nested XSS attempts', () => {
    const nested = '<div><span><script>alert(1)</script></span></div>';
    const sanitized = sanitizeHTML(nested);
    runner.assert(!sanitized.includes('<script'));
    runner.assert(!sanitized.includes('alert'));
});

// ============================================================================
// Run Tests and Report
// ============================================================================

const success = runner.report();

if (success) {
    console.log('\n✅ All tests passed!');
    process.exit(0);
} else {
    console.log('\n❌ Some tests failed!');
    process.exit(1);
}