<?php

use PHPUnit\Framework\TestCase;
use TrustComponent\TrustCaptcha\CaptchaManager;
use TrustComponent\TrustCaptcha\SecretKeyInvalidException;
use TrustComponent\TrustCaptcha\VerificationNotFoundException;
use TrustComponent\TrustCaptcha\VerificationNotFinishedException;
use TrustComponent\TrustCaptcha\VerificationTokenInvalidException;

class CaptchaManagerTest extends TestCase {

    const VALID_TOKEN = "eyJhcGlFbmRwb2ludCI6Imh0dHBzOi8vYXBpLnRydXN0Y29tcG9uZW50LmNvbSIsInZlcmlmaWNhdGlvbklkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiZW5jcnlwdGVkQWNjZXNzVG9rZW4iOiJ0b2tlbiJ9";
    const NOT_FOUND_TOKEN = "eyJhcGlFbmRwb2ludCI6Imh0dHBzOi8vYXBpLnRydXN0Y29tcG9uZW50LmNvbSIsInZlcmlmaWNhdGlvbklkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAxIiwiZW5jcnlwdGVkQWNjZXNzVG9rZW4iOiJ0b2tlbiJ9";
    const LOCKED_TOKEN = "eyJhcGlFbmRwb2ludCI6Imh0dHBzOi8vYXBpLnRydXN0Y29tcG9uZW50LmNvbSIsInZlcmlmaWNhdGlvbklkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAyIiwiZW5jcnlwdGVkQWNjZXNzVG9rZW4iOiJ0b2tlbiJ9";

    public function testSuccessfulVerification() {
        $result = CaptchaManager::getVerificationResult("secret-key", self::VALID_TOKEN);
        $this->assertEquals("00000000-0000-0000-0000-000000000000", $result->verificationId);
    }

    public function testInvalidVerificationToken() {
        $this->expectException(VerificationTokenInvalidException::class);
        CaptchaManager::getVerificationResult("secret-key", "invalid-base64");
    }

    public function testVerificationNotFound() {
        $this->expectException(VerificationNotFoundException::class);
        CaptchaManager::getVerificationResult("secret-key", self::NOT_FOUND_TOKEN);
    }

    public function testSecretKeyInvalid() {
        $this->expectException(SecretKeyInvalidException::class);
        CaptchaManager::getVerificationResult("invalid-key", self::VALID_TOKEN);
    }

    public function testVerificationNotFinished() {
        $this->expectException(VerificationNotFinishedException::class);
        CaptchaManager::getVerificationResult("secret-key", self::LOCKED_TOKEN);
    }
}
