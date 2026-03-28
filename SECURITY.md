# 🔒 Security Policy

## Reporting a Vulnerability

We take the security of Eyes Cerberus seriously. If you discover a security vulnerability, please follow these steps:

### DO NOT

- ❌ Do not open a public issue on GitHub
- ❌ Do not disclose the vulnerability publicly
- ❌ Do not share sensitive information in public channels

### DO

- ✅ Send a detailed report to: [YOUR_EMAIL_HERE]
- ✅ Include steps to reproduce the issue
- ✅ Provide potential impact assessment
- ✅ Allow reasonable time for response and fix

## What to Include

When reporting a vulnerability, please include:

1. **Description** - Clear description of the vulnerability
2. **Impact** - What could an attacker achieve?
3. **Reproduction** - Steps to reproduce the issue
4. **Affected Versions** - Which versions are affected?
5. **Suggested Fix** - If you have suggestions

## Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Fix Timeline**: Depends on severity (will be communicated)

## Security Best Practices

### Before Deploying

- [ ] Review all scripts for your environment
- [ ] Update C2 IPs in `defense_config.cfg`
- [ ] Configure whitelist for your processes
- [ ] Test in isolated environment first

### After Deployment

- [ ] Monitor logs regularly
- [ ] Update known malware hashes
- [ ] Review and rotate any credentials
- [ ] Keep the system updated

## Known Limitations

This system:
- Does NOT replace antivirus software
- Does NOT guarantee 100% protection
- Does NOT delete malware (preserves evidence)
- Requires root/admin privileges

## Security Audit Checklist

Before making this system public:

- [ ] No API keys in code
- [ ] No passwords in configs
- [ ] No personal information
- [ ] No internal IP addresses
- [ ] No SSH keys
- [ ] All credentials use placeholders

---

**Thank you for helping keep Eyes Cerberus secure!** 👁️
