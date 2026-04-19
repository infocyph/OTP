<?php

use Infocyph\OTP\Exceptions\OCRAException;
use Infocyph\OTP\OCRA;
use Infocyph\OTP\Stores\InMemoryReplayStore;

const KEY_20 = '12345678901234567890';
const KEY_32 = "12345678901234567890123456789012";
const KEY_64 = "1234567890123456789012345678901234567890123456789012345678901234";

test('OCRA-1:HOTP-SHA1-6:QN08', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', KEY_20);
    expect($ocra->generate('00000000'))->toBe('237653')
        ->and($ocra->generate('11111111'))->toBe('243178')
        ->and($ocra->generate('22222222'))->toBe('653583')
        ->and($ocra->generate('33333333'))->toBe('740991')
        ->and($ocra->generate('44444444'))->toBe('608993')
        ->and($ocra->generate('55555555'))->toBe('388898')
        ->and($ocra->generate('66666666'))->toBe('816933')
        ->and($ocra->generate('77777777'))->toBe('224598')
        ->and($ocra->generate('88888888'))->toBe('750600')
        ->and($ocra->generate('99999999'))->toBe('294470');
});

test('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', KEY_32);
    $ocra->setPin('1234');
    expect($ocra->generate('12345678', 0))->toBe('65347737')
        ->and($ocra->generate('12345678', 1))->toBe('86775851')
        ->and($ocra->generate('12345678', 2))->toBe('78192410')
        ->and($ocra->generate('12345678', 3))->toBe('71565254')
        ->and($ocra->generate('12345678', 4))->toBe('10104329')
        ->and($ocra->generate('12345678', 5))->toBe('65983500')
        ->and($ocra->generate('12345678', 6))->toBe('70069104')
        ->and($ocra->generate('12345678', 7))->toBe('91771096')
        ->and($ocra->generate('12345678', 8))->toBe('75011558')
        ->and($ocra->generate('12345678', 9))->toBe('08522129');
});

test('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', KEY_32);
    $ocra->setPin('1234');
    expect($ocra->generate('00000000'))->toBe('83238735')
        ->and($ocra->generate('11111111'))->toBe('01501458')
        ->and($ocra->generate('22222222'))->toBe('17957585')
        ->and($ocra->generate('33333333'))->toBe('86776967')
        ->and($ocra->generate('44444444'))->toBe('86807031');
});

test('OCRA-1:HOTP-SHA512-8:C-QN08', function(){
    $ocra = new OCRA('OCRA-1:HOTP-SHA512-8:C-QN08', KEY_64);
    expect($ocra->generate('00000000', 0))->toBe('07016083')
        ->and($ocra->generate('11111111', 1))->toBe('63947962')
        ->and($ocra->generate('22222222', 2))->toBe('70123924')
        ->and($ocra->generate('33333333', 3))->toBe('25341727')
        ->and($ocra->generate('44444444', 4))->toBe('33203315')
        ->and($ocra->generate('55555555', 5))->toBe('34205738')
        ->and($ocra->generate('66666666', 6))->toBe('44343969')
        ->and($ocra->generate('77777777', 7))->toBe('51946085')
        ->and($ocra->generate('88888888', 8))->toBe('20403879')
        ->and($ocra->generate('99999999', 9))->toBe('31409299');
});

test('OCRA-1:HOTP-SHA512-8:QN08-T1M', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA512-8:QN08-T1M', KEY_64);
    $ocra->setTime(new DateTimeImmutable('Mar 25 2008, 12:06:30 GMT'));
    expect($ocra->generate('00000000'))->toBe('95209754')
        ->and($ocra->generate('11111111'))->toBe('55907591')
        ->and($ocra->generate('22222222'))->toBe('22048402')
        ->and($ocra->generate('33333333'))->toBe('24218844')
        ->and($ocra->generate('44444444'))->toBe('36209546');
});

test('OCRA-1:HOTP-SHA256-8:QA08', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', KEY_32);
    expect($ocra->generate('CLI22220SRV11110'))->toBe('28247970')
        ->and($ocra->generate('CLI22221SRV11111'))->toBe('01984843')
        ->and($ocra->generate('CLI22222SRV11112'))->toBe('65387857')
        ->and($ocra->generate('CLI22223SRV11113'))->toBe('03351211')
        ->and($ocra->generate('CLI22224SRV11114'))->toBe('83412541');
});

test('OCRA verifies with and without counter correctly', function () {
    $withCounter = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', KEY_32);
    $withCounter->setPin('1234');
    $otpWithCounter = $withCounter->generate('12345678', 2);

    $withoutCounter = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', KEY_32);
    $withoutCounter->setPin('1234');
    $otpWithoutCounter = $withoutCounter->generate('12345678');

    expect($withCounter->verify($otpWithCounter, '12345678', 2))->toBeTrue()
        ->and($withCounter->verify($otpWithCounter, '12345678', 3))->toBeFalse()
        ->and($withoutCounter->verify($otpWithoutCounter, '12345678'))->toBeTrue();
});

test('OCRA pin optional changes output and missing pin is rejected when required', function () {
    $pinSuite = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', KEY_32);
    $pinSuite->setPin('1234');
    $withPin = $pinSuite->generate('00000000');

    $sameSuiteDifferentPin = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', KEY_32);
    $sameSuiteDifferentPin->setPin('5678');
    $withDifferentPin = $sameSuiteDifferentPin->generate('00000000');

    $noPinSuite = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', KEY_20);
    $withoutPin = $noPinSuite->generate('00000000');

    expect($withPin)->not->toBe($withDifferentPin)
        ->and($withoutPin)->toBe('237653');

    $missingPinSuite = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-PSHA1', KEY_32);
    $missingPinAction = fn () => $missingPinSuite->generate('00000000');
    expect($missingPinAction)->toThrow(OCRAException::class, 'Missing PIN');
});

test('OCRA session optional requires session and changes output', function () {
    $withSession = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', KEY_32);
    $withSession->setSession('A1B2C3D4');
    $otpWithSession = $withSession->generate('12345678');

    $differentSession = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', KEY_32);
    $differentSession->setSession('B1C2D3E4');
    $otpDifferentSession = $differentSession->generate('12345678');

    expect($otpWithSession)->not->toBe($otpDifferentSession);

    $missingSessionSuite = new OCRA('OCRA-1:HOTP-SHA256-8:QN08-S064', KEY_32);
    $missingSessionAction = fn () => $missingSessionSuite->generate('12345678');
    expect($missingSessionAction)->toThrow(OCRAException::class, 'Missing Session');
});

test('OCRA time optional changes output across time slices', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA512-8:QN08-T1M', KEY_64);
    $ocra->setTime(new DateTimeImmutable('Mar 25 2008, 12:06:30 GMT'));
    $first = $ocra->generate('11111111');

    $ocra->setTime(new DateTimeImmutable('Mar 25 2008, 12:07:30 GMT'));
    $second = $ocra->generate('11111111');

    expect($first)->toBe('55907591')
        ->and($second)->not->toBe($first);
});

test('OCRA replay protection rejects reusing accepted challenge and counter combination', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', KEY_32);
    $ocra->setPin('1234');
    $store = new InMemoryReplayStore();
    $otp = $ocra->generate('12345678', 4);

    $first = $ocra->verifyWithResult($otp, '12345678', 4, $store, 'user-42');
    $second = $ocra->verifyWithResult($otp, '12345678', 4, $store, 'user-42');

    expect($first->matched)->toBeTrue()
        ->and($second->matched)->toBeFalse()
        ->and($second->replayDetected)->toBeTrue();
});

test('OCRA exposes parsed suite details', function () {
    $ocra = new OCRA('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1', KEY_32);
    $suite = $ocra->getSuite();

    expect($suite->suite)->toBe('OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1')
        ->and($suite->algorithm)->toBe('sha256')
        ->and($suite->digits)->toBe(8)
        ->and($suite->counterEnabled)->toBeTrue()
        ->and($suite->challengeFormat)->toBe('n')
        ->and($suite->challengeLength)->toBe(8)
        ->and($suite->optionals)->toHaveCount(1)
        ->and($suite->optionals[0]['format'])->toBe('p')
        ->and($suite->optionals[0]['value'])->toBe('SHA1');
});

test('OCRA rejects invalid challenge formats', function () {
    $numeric = new OCRA('OCRA-1:HOTP-SHA1-6:QN08', KEY_20);
    $alpha = new OCRA('OCRA-1:HOTP-SHA256-8:QA08', KEY_32);
    $hex = new OCRA('OCRA-1:HOTP-SHA256-8:QH08', KEY_32);

    expect(fn () => $numeric->generate('ABC12345'))->toThrow(OCRAException::class)
        ->and(fn () => $alpha->generate(str_repeat('A', 129)))->toThrow(OCRAException::class)
        ->and(fn () => $hex->generate('XYZ'))->toThrow(OCRAException::class);
});
