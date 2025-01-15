import protocol


def test_hash_function_consistency():
    """
    Test that protocol.calc_hash produces consistent output for the same input.
    """
    test_messages = [
        b"hello world",
        b"another test message",
        b"1234567890",
        b"!@#$%^&*()",
        b"",
        b"\x00\x01\x02\x03\x04\x05"
    ]

    # Store hash results for each message
    results = {}

    for message in test_messages:
        # Calculate the hash multiple times for the same message
        hash1 = protocol.calc_hash(message)
        hash2 = protocol.calc_hash(message)
        hash3 = protocol.calc_hash(message)

        # Assert that the hash is consistent
        assert hash1 == hash2 == hash3, f"Hash inconsistency for message: {message}"

        # Store the hash result
        results[message] = hash1

    print("All tests passed. Hash is consistent for the same input.")


# Run the test
if __name__ == "__main__":
    test_hash_function_consistency()
