<?php

use Infocyph\OTP\OCRA;

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
