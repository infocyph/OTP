<?php

declare(strict_types=1);

use Infocyph\OTP\Result\VerificationResult;
use Infocyph\OTP\VerificationReason;

test('verification result factories reject contradictory success state', function () {
    expect(fn () => VerificationResult::success(
        VerificationReason::Matched,
        driftOffset: 1,
    ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => VerificationResult::success(
            VerificationReason::Drifted,
            driftOffset: 1,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => VerificationResult::success(
            VerificationReason::Drifted,
            matchedTimestep: 10,
            matchedCounter: 2,
            driftOffset: 1,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => VerificationResult::success(
            VerificationReason::Resynchronized,
            matchedCounter: 10,
            nextCounter: 11,
            driftOffset: 0,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => VerificationResult::success(
            VerificationReason::Matched,
            matchedCounter: 10,
        ))->toThrow(InvalidArgumentException::class)
        ->and(fn () => VerificationResult::success(
            VerificationReason::Matched,
            matchedCounter: 10,
            nextCounter: 12,
        ))->toThrow(InvalidArgumentException::class);
});

test('verification result factories retain coherent exact, drift, and counter states', function () {
    $exact = VerificationResult::success(VerificationReason::Matched, matchedTimestep: 10);
    $drifted = VerificationResult::success(
        VerificationReason::Drifted,
        matchedTimestep: 11,
        driftOffset: 1,
    );
    $resynchronized = VerificationResult::success(
        VerificationReason::Resynchronized,
        matchedCounter: 10,
        nextCounter: 11,
        driftOffset: 2,
    );
    $exhausted = VerificationResult::success(
        VerificationReason::Matched,
        matchedCounter: PHP_INT_MAX,
    );

    expect($exact->isExact())->toBeTrue()
        ->and($drifted->isDrifted())->toBeTrue()
        ->and($resynchronized->nextCounter)->toBe(11)
        ->and($exhausted->nextCounter)->toBeNull();
});
