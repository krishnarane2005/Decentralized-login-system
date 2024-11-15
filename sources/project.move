module DecentralizedLoginSystem::DecentralizedLogin {
    use std::string::String;
    use std::signer;
    use std::error;
    use aptos_framework::account;
    use aptos_framework::event;

    /// Error codes
    const E_USER_ALREADY_REGISTERED: u64 = 1;
    const E_USER_NOT_REGISTERED: u64 = 2;
    const E_INVALID_CREDENTIALS: u64 = 3;

    /// Struct to store user credentials
    struct UserCredentials has key {
        username: String,
        password_hash: String,  // Store hashed password, never plain text
        is_active: bool
    }

    /// Event for tracking login attempts
    struct LoginAttemptEvent has drop, store {
        user_address: address,
        success: bool,
        timestamp: u64
    }

    /// Function to register a new user with credentials
    public fun register_user(
        account: &signer,
        username: String,
        password_hash: String
    ) {
        let user_addr = signer::address_of(account);
        
        // Check if user is already registered
        assert!(!exists<UserCredentials>(user_addr), error::already_exists(E_USER_ALREADY_REGISTERED));

        // Create new user credentials
        let credentials = UserCredentials {
            username,
            password_hash,
            is_active: true
        };

        // Store credentials in user's account
        move_to(account, credentials);
    }

    /// Function to verify user credentials and log in
    public fun verify_login(
        account: &signer,
        password_hash: String
    ): bool acquires UserCredentials {
        let user_addr = signer::address_of(account);
        
        // Verify user exists
        assert!(exists<UserCredentials>(user_addr), error::not_found(E_USER_NOT_REGISTERED));
        
        let credentials = borrow_global<UserCredentials>(user_addr);
        let success = credentials.password_hash == password_hash && credentials.is_active;

        // Emit login attempt event
        event::emit(LoginAttemptEvent {
            user_address: user_addr,
            success,
            timestamp: aptos_framework::timestamp::now_microseconds()
        });

        success
    }
}