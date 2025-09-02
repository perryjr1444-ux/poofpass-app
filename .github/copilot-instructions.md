# PoofPass (Hashword) - GitHub Copilot Coding Instructions

**PoofPass** is a revolutionary unhackable password system with automatic rotation after each login attempt. The application is built with Next.js, TypeScript, Supabase, and implements zero-trust architecture with military-grade security.

**ALWAYS follow these instructions first and only fallback to additional search and context gathering if the information here is incomplete or found to be in error.**

## Working Effectively

### Bootstrap and Setup
Run these commands in exact order to set up the development environment:

```bash
# 1. Install dependencies (takes ~35 seconds)
npm install

# 2. Set up environment variables
cp .env.example .env.local
# Edit .env.local with your Supabase credentials:
# NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
# NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
# SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
# NEXT_PUBLIC_SITE_URL=http://localhost:3000

# 3. Start development server (takes ~1.4 seconds)
npm run dev
```

### Build and Test Commands

**CRITICAL BUILD STATUS**: The production build currently fails due to ESLint errors but the development server works perfectly.

```bash
# Development server (ALWAYS WORKS)
npm run dev                    # Takes 1.4 seconds, runs on http://localhost:3000

# Production build (CURRENTLY FAILS - known issue)
npm run build                  # NEVER CANCEL: Takes ~12 seconds, fails due to ESLint errors

# Type checking (CURRENTLY FAILS - known issue)  
npm run typecheck              # NEVER CANCEL: Set timeout to 120+ seconds, has TypeScript errors

# Linting (HAS ERRORS - known issue)
npm run lint                   # Takes ~10 seconds, has React hooks violations

# Testing (WORKS but no tests exist)
npm run test -- --passWithNoTests  # Takes ~1 second, passes with no tests
npm run test:ci                     # For CI environment
npm run test:coverage               # For coverage reports

# Security audit (WORKS)
npm audit                      # Takes ~5 seconds, currently 0 vulnerabilities
```

### **NEVER CANCEL WARNINGS**
- **NEVER CANCEL** any build or test command - Set timeouts of 120+ seconds minimum
- **NEVER CANCEL** npm install - Can take up to 60 seconds in some environments
- **NEVER CANCEL** type checking - TypeScript compilation can take several minutes

## Validation Scenarios

### **MANDATORY**: Always test these scenarios after making changes:

1. **Development Server Test**:
   ```bash
   npm run dev
   # Wait for "Ready" message
   # Open http://localhost:3000
   # Verify homepage loads with "Hashword · Rotate-on-use secrets"
   # Test navigation to /login, /pricing, /terms, /privacy
   ```

2. **Login Flow Validation**:
   ```bash
   # Navigate to http://localhost:3000/login
   # Verify email input field appears
   # Verify "Email me a link" button is present
   # Verify "QR one-time code" button works
   ```

3. **Core Functionality Test**:
   ```bash
   # Test that main features are accessible
   # Verify password rotation concepts are explained
   # Check API documentation is reachable
   ```

## Known Issues and Workarounds

### Current Build Failures
The build fails due to these specific ESLint errors:
- `app/dashboard/page.tsx`: React Hook "usePassword" called inside callback
- `app/terms/page.tsx`: Unescaped quotes in JSX
- `lib/hooks/use-notifications.tsx`: React Hook rules violations

**Workaround**: Use development server (`npm run dev`) for testing changes. Production build needs ESLint fixes.

### TypeScript Errors
Current TypeScript errors in:
- `lib/backup/recovery.ts`: Unknown error types need proper typing
- `lib/pwa/service-worker.ts`: Missing registration property

**Workaround**: Development still works; fix types when working on these files.

### Missing Test Suite
**IMPORTANT**: This project has no test files. Always manually validate changes.

## Project Structure

### Key Directories
```
/app                    # Next.js App Router pages
├── api/               # API routes
├── dashboard/         # Password management dashboard  
├── login/             # Authentication pages
└── ...

/lib                   # Core business logic
├── auth/              # Authentication utilities
├── crypto/            # Encryption and security
├── database/          # Database operations
├── hooks/             # React hooks
└── ...

/components            # Reusable UI components
├── ui/                # shadcn/ui components
└── shell/             # Layout components

/supabase              # Supabase configuration
├── functions/         # Edge functions (vault-store, vault-reveal, otac-*)
└── migrations/        # Database migrations

/scripts               # Utility scripts
└── security-assessment.sh  # Security validation script
```

### Important Files
- `middleware.ts` - Route protection and security headers
- `next.config.mjs` - Next.js configuration with security settings
- `lighthouserc.js` - Performance and security testing
- `.cursor/` - MCP integration guides and configurations

## Environment Requirements

### Required Environment Variables
```bash
# Core Supabase (Required for all functionality)
NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Application Settings
NEXT_PUBLIC_SITE_URL=http://localhost:3000
NEXT_PUBLIC_SUPPORT_EMAIL=support@poofpass.com

# Security Keys (Generate with: openssl rand -base64 32)
VAULT_KEK=your-key-encryption-key
VAULT_POINTER_PEPPER=your-pointer-pepper
OTAC_PEPPER=your-otac-pepper
ADMIN_BOOTSTRAP_SECRET=your-admin-secret

# Optional: Monitoring and Analytics
NEXT_PUBLIC_SENTRY_DSN=your-sentry-dsn
SENTRY_AUTH_TOKEN=your-auth-token
NEXT_PUBLIC_POSTHOG_KEY=your-posthog-key
```

### External Dependencies
- **Node.js 18.x+** (required)
- **Supabase project** (required for backend)
- **Supabase CLI** (optional, for database operations)

## Development Workflow

### Making Changes
1. **Always start with**: `npm run dev`
2. **Test changes manually** in browser at http://localhost:3000
3. **Validate core workflows**: login, navigation, password concepts
4. **Run security checks**: `npm audit`
5. **Check for new TypeScript errors**: `npm run typecheck` (expect existing failures)

### Before Committing
```bash
# 1. Manual validation (REQUIRED)
npm run dev
# Test complete user flow in browser

# 2. Security audit (should pass)
npm audit

# 3. Try linting (expect failures)
npm run lint

# 4. Note: Cannot run build due to current ESLint errors
```

## Security and Compliance

### Security Validation
Run the comprehensive security assessment:
```bash
./scripts/security-assessment.sh
# NEVER CANCEL: Takes 5-10 minutes depending on system
# NOTE: Requires 'ramparts' CLI tool to be installed first
# Will exit early if dependencies are missing
# Generates reports in .cursor/security-reports/ when all dependencies available
```

**Installing Ramparts for Security Assessment**:
```bash
# Install Ramparts (Rust-based security scanner)
cargo install ramparts
# OR follow installation guide at ramparts documentation
```

### Security Features Implemented
- AES-256-GCM encryption for all sensitive data
- Automatic password rotation after login attempts  
- Hash-based password generation with cryptographic security
- Zero-knowledge architecture with client-side encryption
- WebAuthn/FIDO2 biometric authentication support
- Advanced session management with device tracking
- Rate limiting with circuit breakers
- Comprehensive security headers and CSP

## CI/CD Integration

### GitHub Actions Workflows
The repository includes comprehensive CI/CD:
- `.github/workflows/ci.yml` - Main CI/CD pipeline
- `.github/workflows/security.yml` - Security scanning
- Lighthouse performance testing
- SAST scanning with CodeQL
- Dependency vulnerability scanning

**Note**: CI builds will fail until ESLint errors are resolved.

## Troubleshooting

### Common Issues

1. **"Module not found" errors**: Run `npm install`
2. **Build fails with ESLint errors**: Expected - use `npm run dev` instead
3. **TypeScript errors**: Expected - dev server still works
4. **Port 3000 in use**: Kill existing process or use `npm run dev -- -p 3001`
5. **Supabase connection errors**: Check .env.local credentials

### Emergency Recovery
If development environment breaks:
```bash
# Full reset
rm -rf node_modules package-lock.json
npm install
npm run dev
```

## Performance Expectations

### Command Timing
- `npm install`: 35-60 seconds (NEVER CANCEL)
- `npm run dev`: 1-2 seconds  
- `npm run build`: 12 seconds (currently fails)
- `npm run typecheck`: 30-120 seconds (NEVER CANCEL)
- `npm audit`: 5-10 seconds
- `./scripts/security-assessment.sh`: 5-10 minutes (NEVER CANCEL)

### Application Performance
- Development server startup: ~1.4 seconds
- Hot reload: <1 second
- Page navigation: <200ms
- Initial page load: <2 seconds

## Application Context

**Core Concept**: PoofPass (branded as "Hashword") implements revolutionary password security through automatic rotation after each login attempt, making passwords truly unhackable by design.

**Key Features**:
- Auto-rotating passwords that change after each use
- Zero-trust architecture with end-to-end encryption
- Real-time WebSocket synchronization  
- Team collaboration capabilities
- Comprehensive audit logging
- Progressive Web App with offline capabilities

**Technology Stack**:
- **Frontend**: Next.js 14, TypeScript, TailwindCSS, shadcn/ui
- **Backend**: Supabase (Auth, Database, Edge Functions)
- **Security**: AES-256-GCM, WebAuthn, FIDO2
- **Monitoring**: Sentry, PostHog
- **Testing**: Jest (no tests currently implemented)

## Quick Reference Commands

```bash
# Essential daily commands
npm run dev                           # Start development (ALWAYS WORKS)
npm audit                            # Security check (should pass)
npm run test -- --passWithNoTests   # Test runner (no tests exist)

# Troubleshooting
npm install                          # Reinstall dependencies  
rm -rf .next && npm run dev         # Clear Next.js cache

# Documentation locations
docs/DEPLOYMENT.md                   # Production deployment guide
docs/ENVIRONMENT_SETUP.md           # Environment configuration
.cursor/MCP_INTEGRATION_GUIDE.md    # Development tools setup
```

---

**Remember**: Always test manually after making changes since automated tests don't exist. The development server works reliably even though production builds currently fail due to ESLint configuration issues.