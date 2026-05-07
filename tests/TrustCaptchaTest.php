<?php

use PHPUnit\Framework\TestCase;
use TrustComponent\TrustCaptcha\TrustCaptcha;
use TrustComponent\TrustCaptcha\ApiKeyInvalidException;
use TrustComponent\TrustCaptcha\VerificationNotFoundException;
use TrustComponent\TrustCaptcha\VerificationNotFinishedException;
use TrustComponent\TrustCaptcha\VerificationTokenInvalidException;
use TrustComponent\TrustCaptcha\VerificationResultExpiredException;
use TrustComponent\TrustCaptcha\VerificationResultRetrievalLimitReachedException;
use TrustComponent\TrustCaptcha\ServerUnreachableException;

class TrustCaptchaTest extends TestCase {

    const VALID_TOKEN = "eyJ2ZXJpZmljYXRpb25JZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCJ9";
    const NOT_FOUND_TOKEN = "eyJ2ZXJpZmljYXRpb25JZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSJ9";
    const LOCKED_TOKEN = "eyJ2ZXJpZmljYXRpb25JZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMiJ9";
    const EXPIRED_TOKEN = "eyJ2ZXJpZmljYXRpb25JZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMyJ9";
    const LIMIT_REACHED_TOKEN = "eyJ2ZXJpZmljYXRpb25JZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwNCJ9";
    const TOKEN_WITH_UNKNOWN_FIELDS = "eyJ2ZXJpZmljYXRpb25JZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMCIsInVua25vd25GaWVsZCI6ImZvbyIsImFub3RoZXJKdW5rIjo0MiwibmVzdGVkIjp7IngiOjF9fQ==";

    private function tc(string $apiKey = "ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"): TrustCaptcha {
        return new TrustCaptcha($apiKey);
    }

    public function testSuccessfulVerification() {
        $result = $this->tc()->getVerificationResult(self::VALID_TOKEN);
        $this->assertEquals("00000000-0000-0000-0000-000000000000", $result->verificationId);
    }

    public function testInvalidVerificationToken() {
        $this->expectException(VerificationTokenInvalidException::class);
        $this->tc()->getVerificationResult("invalid-base64");
    }

    public function testVerificationTokenInvalidWhenBase64ButNotJson() {
        // base64("not-a-json")
        $this->expectException(VerificationTokenInvalidException::class);
        $this->tc()->getVerificationResult("bm90LWEtanNvbg==");
    }

    public function testVerificationTokenInvalidWhenJsonMissingVerificationId() {
        // base64('{"foo":"bar"}')
        $this->expectException(VerificationTokenInvalidException::class);
        $this->tc()->getVerificationResult("eyJmb28iOiJiYXIifQ==");
    }

    public function testVerificationNotFound() {
        $this->expectException(VerificationNotFoundException::class);
        $this->tc()->getVerificationResult(self::NOT_FOUND_TOKEN);
    }

    public function testApiKeyInvalid() {
        $this->expectException(ApiKeyInvalidException::class);
        $this->tc("invalid-key")->getVerificationResult(self::VALID_TOKEN);
    }

    public function testVerificationNotFinished() {
        $this->expectException(VerificationNotFinishedException::class);
        $this->tc()->getVerificationResult(self::LOCKED_TOKEN);
    }

    public function testVerificationResultExpired() {
        $this->expectException(VerificationResultExpiredException::class);
        $this->tc()->getVerificationResult(self::EXPIRED_TOKEN);
    }

    public function testVerificationResultRetrievalLimitReached() {
        $this->expectException(VerificationResultRetrievalLimitReachedException::class);
        $this->tc()->getVerificationResult(self::LIMIT_REACHED_TOKEN);
    }

    public function testToleratesUnknownFieldsInVerificationToken() {
        $result = $this->tc()->getVerificationResult(self::TOKEN_WITH_UNKNOWN_FIELDS);
        $this->assertEquals("00000000-0000-0000-0000-000000000000", $result->verificationId);
    }

    public function testThrowsServerUnreachableExceptionWhenApiHostUnreachable() {
        $this->expectException(ServerUnreachableException::class);
        $tc = new TrustCaptcha("ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", ["apiHost" => "http://localhost:1", "connectTimeoutMs" => 500, "readTimeoutMs" => 500]);
        $tc->getVerificationResult(self::VALID_TOKEN);
    }
}
