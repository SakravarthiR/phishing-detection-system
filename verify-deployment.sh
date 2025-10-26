#!/bin/bash

# Pre-Deployment Verification Script
# Run this before deploying to catch any issues

echo "========================================="
echo "PRE-DEPLOYMENT VERIFICATION"
echo "========================================="

ERRORS=0
WARNINGS=0

# Check 1: Required files exist
echo ""
echo "Checking required files..."
FILES=(
    ".env.example"
    ".gitignore"
    ".htaccess"
    "robots.txt"
    "README.md"
    "DEPLOYMENT.md"
    "SECURITY.md"
    "backend/secure_api.py"
    "backend/phish_detector.py"
    "backend/requirements.txt"
    "deployment/deploy.sh"
    "deployment/nginx.conf"
    "deployment/phishing-detector.service"
    "frontend/index.html"
    "frontend/login.html"
    "frontend/scanner.html"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file exists"
    else
        echo "  ✗ MISSING: $file"
        ((ERRORS++))
    fi
done

# Check 2: Sensitive files NOT present (should be in .gitignore)
echo ""
echo "Checking sensitive files are excluded..."
SENSITIVE=(
    ".env"
    "credentials.json"
    "__pycache__"
)

for file in "${SENSITIVE[@]}"; do
    if [ -e "$file" ] || [ -d "$file" ]; then
        if grep -q "$file" .gitignore; then
            echo "  ✓ $file exists but is in .gitignore"
        else
            echo "  ✗ WARNING: $file exists but NOT in .gitignore!"
            ((WARNINGS++))
        fi
    else
        echo "  ✓ $file not present (good)"
    fi
done

# Check 3: Python requirements file is valid
echo ""
echo "Checking Python requirements..."
if [ -f "backend/requirements.txt" ]; then
    if grep -q "Flask" backend/requirements.txt && \
       grep -q "scikit-learn" backend/requirements.txt; then
        echo "  ✓ requirements.txt looks valid"
    else
        echo "  ✗ requirements.txt missing key packages"
        ((ERRORS++))
    fi
fi

# Check 4: Deploy script is executable
echo ""
echo "Checking deployment script..."
if [ -f "deployment/deploy.sh" ]; then
    if [ -x "deployment/deploy.sh" ]; then
        echo "  ✓ deploy.sh is executable"
    else
        echo "  ! deploy.sh is not executable (will fix automatically)"
        chmod +x deployment/deploy.sh
        echo "  ✓ Fixed: deploy.sh is now executable"
    fi
fi

# Check 5: Git repository initialized
echo ""
echo "Checking Git configuration..."
if [ -d ".git" ]; then
    echo "  ✓ Git repository initialized"
    
    # Check if remote is set
    if git remote -v | grep -q "origin"; then
        echo "  ✓ Git remote 'origin' is configured"
    else
        echo "  ! No git remote 'origin' configured"
        ((WARNINGS++))
    fi
else
    echo "  ! Git not initialized (run 'git init')"
    ((WARNINGS++))
fi

# Check 6: README has proper content
echo ""
echo "Checking README.md..."
if grep -q "Phishing Detection System" README.md; then
    echo "  ✓ README.md has project title"
else
    echo "  ✗ README.md missing or incomplete"
    ((ERRORS++))
fi

# Check 7: No hardcoded localhost URLs in frontend (common mistake)
echo ""
echo "Checking frontend API URLs..."
if grep -r "localhost:5000" frontend/*.js 2>/dev/null; then
    echo "  ! WARNING: Found localhost URLs in frontend JS files"
    echo "    Remember to update these to your production domain!"
    ((WARNINGS++))
else
    echo "  ✓ No localhost URLs found in frontend"
fi

# Summary
echo ""
echo "========================================="
echo "VERIFICATION SUMMARY"
echo "========================================="
echo "Errors: $ERRORS"
echo "Warnings: $WARNINGS"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo "✓ No critical errors found!"
    if [ $WARNINGS -eq 0 ]; then
        echo "✓ Project is ready for deployment!"
        echo ""
        echo "Next steps:"
        echo "1. Push to GitHub: git push origin main"
        echo "2. Follow HOSTING_PROCEDURE.md"
        exit 0
    else
        echo "! Some warnings found - review them before deploying"
        exit 0
    fi
else
    echo "✗ Critical errors found - fix them before deploying!"
    exit 1
fi
