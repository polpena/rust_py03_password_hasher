import password_hasher

def test_password_hasher():
    try:
        # Test 1: Hash a password and verify it
        print("Test 1: Hash and verify a valid password")
        password = "ap3!sin2004"
        hashed = password_hasher.hash_password(password)
        print("Hashed password:", hashed)

        is_valid = password_hasher.verify_password(password, hashed)
        print("Is valid:", is_valid)
        assert is_valid, "Password verification failed for a correct password"

        # Test 2: Verify with an incorrect password
        print("\nTest 2: Verify with an incorrect password")
        is_invalid = password_hasher.verify_password("wrong_password", hashed)
        print("Is valid with wrong password:", is_invalid)
        assert not is_invalid, "Password verification incorrectly succeeded for a wrong password"

        # Test 3: Ensure hashing the same password yields different results
        print("\nTest 3: Check that hashes are unique for the same password")
        hashed2 = password_hasher.hash_password(password)
        print("Second hashed password:", hashed2)
        assert hashed != hashed2, "Hashes should differ for the same password due to random salts"

        # Test 4: Handle invalid hashed password input
        print("\nTest 4: Handle invalid hashed password input")
        try:
            password_hasher.verify_password(password, "invalid_hash_format")
            print("Invalid hash format test: Failed (no exception raised)")
        except ValueError as e:
            print("Invalid hash format test: Passed (exception raised)")
            print("Exception message:", str(e))

        print("\nAll tests passed successfully!")
    except AssertionError as error:
        print("Test failed:", error)

if __name__ == "__main__":
    test_password_hasher()
