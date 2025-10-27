import bcrypt

# The hash from credentials
stored_hash = "$2b$12$00elCabSkbILA0vPwu2azOHBp73Z/HC4Bpw0TsyewDekl5EJQ./Da"
test_password = "phishing123"

# Test if password matches
try:
    # bcrypt.checkpw requires bytes
    result = bcrypt.checkpw(test_password.encode('utf-8'), stored_hash.encode('utf-8'))
    print(f"✅ Password 'phishing123' matches hash: {result}")
except Exception as e:
    print(f"❌ Error: {e}")
    print(f"Error type: {type(e)}")
    print(f"\nTrying with different encoding...")
    try:
        # Try treating hash as already bytes
        result = bcrypt.checkpw(test_password.encode('utf-8'), stored_hash.encode('utf-8'))
        print(f"Result: {result}")
    except Exception as e2:
        print(f"Also failed: {e2}")
