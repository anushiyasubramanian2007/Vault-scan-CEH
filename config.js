/**
 * VaultScan - JWT Security Analyzer Configuration
 * Severity weights, weak secrets dictionary, sensitive patterns, MITRE ATT&CK mapping
 */

const SEVERITY_WEIGHTS = {
  CRITICAL: 40,
  HIGH: 25,
  MEDIUM: 10,
  LOW: 5
};

// 45+ common weak secrets for dictionary verification
const WEAK_SECRETS = [
  'secret', 'secret123', 'password', '123456', 'jwt', 'key',
  'changeme', 'admin', 'test', 'dev', 'your-256-bit-secret',
  'supersecret', 'mysecret', 'token', 'jwtsecret', 'qwerty',
  'letmein', '12345678', '123456789', 'administrator', 'root',
  'default', 'app_secret', 'auth_secret', 'node_auth', 'express',
  'secretkey', 'masterkey', 'privatekey', 'pass123', 'welcome',
  'welcome123', 'hunter2', 'iloveyou', 'sunshine', 'princess',
  'dragon', 'football', 'monkey', 'starwars', 'access_token',
  'my-secret-key', 'jwt_secret_token', 'temp_secret', 'demo_key',
  'smart_grocery_super_secret_key_2026', 'shhhhh'
];

const SENSITIVE_PATTERNS = {
  password: /pass|pwd/i,
  ssn: /ssn|social.?security/i,
  creditCard: /\\b(?:\\d[ -]*?){13,16}\\b/,
  apiKey: /api[_-]?key|apikey/i,
  privateKey: /private[_-]?key/i,
  email: /\\S+@\\S+\\.\\S+/,
  phone: /\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b/
};

const MITRE_MAP = {
  alg_none:          'T1550.001',
  weak_secret:       'T1110.002',
  alg_confusion:     'T1550.001',
  sensitive_payload: 'T1552.001',
  kid_traversal:     'T1083',
  jku_external:      'T1195'
};

module.exports = {
  SEVERITY_WEIGHTS,
  WEAK_SECRETS,
  SENSITIVE_PATTERNS,
  MITRE_MAP
};
