<?php
/**
 * Working OTP Verification Script for Asterisk
 * Local TOTP verification - no Keycloak dependency
 */

// Enable error logging
error_reporting(E_ALL);
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/asterisk/otp_debug.log');

// Get parameters from Asterisk AGI
$username = $argv[1] ?? '';
$otp_code = $argv[2] ?? '';

// Log the attempt
error_log("OTP Verify: Starting verification for user='$username', code='$otp_code', time=" . date('Y-m-d H:i:s'));

if (empty($username) || empty($otp_code)) {
    error_log("OTP Verify: ERROR - Invalid parameters");
    echo "INVALID_PARAMS\n";
    exit(1);
}

function verifyTOTP($username, $otp_code) {
    $secret = getUserTOTPSecret($username);
    
    if (!$secret) {
        error_log("OTP Verify: ERROR - No secret found for user '$username'");
        return false;
    }
    
    error_log("OTP Verify: Found secret for user '$username', length=" . strlen($secret));
    
    // Verify TOTP code with time window (±2 steps = ±1 minute)
    $current_time = floor(time() / 30);
    error_log("OTP Verify: Current time step=$current_time");
    
    // Check codes in time window
    for ($i = -2; $i <= 2; $i++) {
        $test_code = generateTOTP($secret, $current_time + $i);
        error_log("OTP Verify: Time step " . ($current_time + $i) . " generates code '$test_code'");
        
        if ($test_code === $otp_code) {
            error_log("OTP Verify: SUCCESS - Code matches at time step " . ($current_time + $i));
            return true;
        }
    }
    
    error_log("OTP Verify: FAILED - No matching codes found");
    return false;
}

function getUserTOTPSecret($username) {
    $secrets_file = "/etc/asterisk/otp_secrets.json";
    
    if (!file_exists($secrets_file)) {
        error_log("OTP Verify: ERROR - Secrets file not found: $secrets_file");
        return false;
    }
    
    $secrets_content = file_get_contents($secrets_file);
    if ($secrets_content === false) {
        error_log("OTP Verify: ERROR - Cannot read secrets file");
        return false;
    }
    
    $secrets = json_decode($secrets_content, true);
    if ($secrets === null) {
        error_log("OTP Verify: ERROR - Invalid JSON in secrets file: " . json_last_error_msg());
        return false;
    }
    
    if (!isset($secrets[$username])) {
        error_log("OTP Verify: ERROR - User '$username' not found in secrets. Available: " . implode(', ', array_keys($secrets)));
        return false;
    }
    
    return $secrets[$username];
}

function generateTOTP($secret, $time_step) {
    $key = base32_decode($secret);
    if ($key === false || empty($key)) {
        error_log("OTP Verify: ERROR - Failed to decode base32 secret");
        return false;
    }
    
    $time = pack('N*', 0, $time_step);
    $hash = hash_hmac('sha1', $time, $key, true);
    $offset = ord($hash[19]) & 0xf;
    $code = (
        ((ord($hash[$offset+0]) & 0x7f) << 24) |
        ((ord($hash[$offset+1]) & 0xff) << 16) |
        ((ord($hash[$offset+2]) & 0xff) << 8) |
        (ord($hash[$offset+3]) & 0xff)
    ) % 1000000;
    
    return sprintf('%06d', $code);
}

function base32_decode($input) {
    if (empty($input)) {
        return false;
    }
    
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper($input);
    $input = preg_replace('/[^A-Z2-7]/', '', $input);
    
    if (empty($input)) {
        return false;
    }
    
    $output = '';
    $buffer = 0;
    $bitsLeft = 0;
    
    for ($i = 0; $i < strlen($input); $i++) {
        $val = strpos($alphabet, $input[$i]);
        if ($val === false) {
            continue;
        }
        
        $buffer = ($buffer << 5) | $val;
        $bitsLeft += 5;
        
        if ($bitsLeft >= 8) {
            $output .= chr(($buffer >> ($bitsLeft - 8)) & 255);
            $bitsLeft -= 8;
        }
    }
    
    return $output;
}

// Main execution
error_log("OTP Verify: Starting main verification process");

if (verifyTOTP($username, $otp_code)) {
    error_log("OTP Verify: FINAL RESULT - VALID");
    echo "VALID\n";
    exit(0);
} else {
    error_log("OTP Verify: FINAL RESULT - INVALID");
    echo "INVALID\n";
    exit(1);
}
?>
