<?php

declare(strict_types=1);

use Infocyph\OTP\OCRA;
use Infocyph\OTP\Stores\InMemoryReplayStore;
use Infocyph\OTP\ValueObjects\VerificationWindow;

const OCRA_KEY_20 = '12345678901234567890';
const OCRA_KEY_32 = '12345678901234567890123456789012';
const OCRA_KEY_64 = '1234567890123456789012345678901234567890123456789012345678901234';

test('RFC 6287 suites follow the reference byte conversion for numeric challenges', function () {
    $sha1 = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', OCRA_KEY_20);
    $sha256 = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', OCRA_KEY_32);
    $sha512 = new OCRA('OCRA-1:HOTP-SHA512-8:C-QN08', OCRA_KEY_64);
    $sha1Expected = ['237653', '243178', '890740', '869330', '581521', '423328', '288643', '004504', '518526', '721123'];
    $sha256Expected = ['65347737', '86775851', '78192410', '71565254', '10104329', '65983500', '70069104', '91771096', '75011558', '08522129'];
    $sha512Expected = ['07016083', '63947962', '72071755', '88548889', '40500742', '34557787', '40889896', '54898728', '39113879', '06429217'];

    for ($index = 0; $index < 10; $index++) {
        $challenge = str_repeat((string) $index, 8);
        expect($sha1->generate($challenge))->toBe($sha1Expected[$index])
            ->and($sha256->generate('12345678', $index, '1234'))->toBe($sha256Expected[$index])
            ->and($sha512->generate($challenge, $index))->toBe($sha512Expected[$index]);
    }
});

test('RFC 6287 time and explicit mutual challenge vectors remain intact', function () {
    $time = new OCRA('OCRA-1:HOTP-SHA512-8:QN08-T1M', OCRA_KEY_64);
    $timestamp = (new DateTimeImmutable('Mar 25 2008, 12:06:30 GMT'))->getTimestamp();
    $mutual = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', OCRA_KEY_32);

    expect($time->generate('00000000', timestamp: $timestamp))->toBe('95209754')
        ->and($time->generate('11111111', timestamp: $timestamp))->toBe('55907591')
        ->and($mutual->generateMutual('CLI22220', 'SRV11110'))->toBe('28247970')
        ->and($mutual->generateMutual('CLI22224', 'SRV11114'))->toBe('83412541')
        ->and($mutual->generateSignature('SIG10000'))->toBe('53095496');
});

test('odd-nibble numeric and hexadecimal challenges match independent reference outputs', function () {
    $numeric = new OCRA('OCRA-1:HOTP-SHA256-8:QN64', OCRA_KEY_32);
    $hex = new OCRA('OCRA-1:HOTP-SHA256-8:QH64', OCRA_KEY_32);
    $numericVectors = [
        '0' => '28196979',
        '15' => '24289059',
        '16' => '19086334',
        '255' => '45431508',
        '256' => '81618124',
        '4095' => '92780630',
        '4096' => '19086334',
        '1048575' => '24357113',
    ];
    $hexVectors = ['F' => '11932816', 'ABC' => '85619925', 'ABCDE' => '34979433'];

    foreach ($numericVectors as $challenge => $expected) {
        expect($numeric->generate((string) $challenge))->toBe($expected);
    }
    foreach ($hexVectors as $challenge => $expected) {
        expect($hex->generate($challenge))->toBe($expected);
    }
});

test('non-counter OCRA rejects irrelevant counters and cannot vary replay identity', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08', OCRA_KEY_32);
    $store = new InMemoryReplayStore();
    $otp = $ocra->generate('12345678');

    $first = $ocra->verifyWithResult($otp, '12345678', replayStore: $store, factorId: 'factor-v1');
    $second = $ocra->verifyWithResult($otp, '12345678', replayStore: $store, factorId: 'factor-v1');

    expect($first->matched)->toBeTrue()
        ->and($second->replayDetected)->toBeTrue()
        ->and(fn () => $ocra->generate('12345678', 1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $ocra->verify($otp, '12345678', 1))->toThrow(InvalidArgumentException::class);
});

test('counter OCRA advances monotonically and exposes next counter', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', OCRA_KEY_32);
    $store = new InMemoryReplayStore();
    $otp = $ocra->generate('12345678', 4);
    $result = $ocra->verifyWithResult($otp, '12345678', 4, replayStore: $store, factorId: 'factor-v1');

    expect($result->matched)->toBeTrue()
        ->and($result->matchedCounter)->toBe(4)
        ->and($result->nextCounter)->toBe(5)
        ->and($ocra->verifyWithResult($otp, '12345678', 4, replayStore: $store, factorId: 'factor-v1')->replayDetected)->toBeTrue();
});

test('OCRA rejects missing and irrelevant suite inputs', function () {
    $plain = new OCRA('OCRA-1:HOTP-SHA256-8:QN08', OCRA_KEY_32);
    $pin = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', OCRA_KEY_32);
    $session = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', OCRA_KEY_32);
    $time = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-T1M', OCRA_KEY_32);
    $counter = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08', OCRA_KEY_32);

    expect(fn () => $plain->generate('12345678', pin: '1234'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $pin->generate('12345678'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $plain->generate('12345678', session: 'session'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $session->generate('12345678'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $plain->generate('12345678', timestamp: 1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $time->generate('12345678'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $counter->generate('12345678'))->toThrow(InvalidArgumentException::class)
        ->and($session->generate('12345678', session: 'ABC'))
        ->toBe($session->generate('12345678', session: OCRA::sessionHex('414243')));
});

test('OCRA time verification supports explicit bounded drift and replay', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-T1M', OCRA_KEY_32);
    $store = new InMemoryReplayStore();
    $otp = $ocra->generate('12345678', timestamp: 1060);
    $result = $ocra->verifyWithResult(
        $otp,
        '12345678',
        timestamp: 1000,
        timeWindow: new VerificationWindow(0, 1),
        replayStore: $store,
        factorId: 'factor-v1',
        replayTtl: 120,
    );

    expect($result->matched)->toBeTrue()
        ->and($result->driftOffset)->toBe(1)
        ->and($ocra->verifyWithResult(
            $otp,
            '12345678',
            timestamp: 1000,
            timeWindow: new VerificationWindow(0, 1),
            replayStore: $store,
            factorId: 'factor-v1',
            replayTtl: 120,
        )->replayDetected)->toBeTrue()
        ->and($ocra->verifyWithResult(
            $ocra->generate('12345678', timestamp: 1000),
            '12345678',
            timestamp: 1000,
            timeWindow: new VerificationWindow(),
        )->driftOffset)->toBe(0)
        ->and($ocra->verifyWithResult(
            $ocra->generate('12345678', timestamp: 940),
            '12345678',
            timestamp: 1000,
            timeWindow: new VerificationWindow(1),
        )->driftOffset)->toBe(-1)
        ->and($ocra->verify(
            $ocra->generate('12345678', timestamp: 1120),
            '12345678',
            timestamp: 1000,
            timeWindow: new VerificationWindow(1, 1),
        ))->toBeFalse()
        ->and(fn () => $ocra->generate('12345678', timestamp: -1))->toThrow(InvalidArgumentException::class);
});

test('OCRA full-HMAC suites return stable printable hexadecimal', function (string $algorithm, int $length) {
    $ocra = new OCRA(sprintf('OCRA-1:HOTP-%s-0:QN08', strtoupper($algorithm)), OCRA_KEY_64);
    $otp = $ocra->generate('12345678');

    expect($otp)->toHaveLength($length)
        ->toMatch('/^[A-F0-9]+$/')
        ->and($ocra->verify($otp, '12345678'))->toBeTrue()
        ->and($ocra->verify('not-hex', '12345678'))->toBeFalse();
})->with([['sha1', 40], ['sha256', 64], ['sha512', 128]]);

test('OCRA suite parsing is authoritative', function () {
    $suite = (new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1-S064-T1M', OCRA_KEY_32))->getSuite();

    expect($suite->algorithm)->toBe('sha256')
        ->and($suite->digits)->toBe(8)
        ->and($suite->counterEnabled)->toBeTrue()
        ->and($suite->pinAlgorithm)->toBe('sha1')
        ->and($suite->sessionLength)->toBe(64)
        ->and($suite->timeStepSeconds)->toBe(60)
        ->and(fn () => new OCRA('OCRA-1:HOTP-SHA256-10:QN08', OCRA_KEY_32))->toThrow(InvalidArgumentException::class);
});
