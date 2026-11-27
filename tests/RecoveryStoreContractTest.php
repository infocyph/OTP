<?php

declare(strict_types=1);

namespace Infocyph\OTP\Tests;

use DateTimeImmutable;
use Infocyph\OTP\Contracts\RecoveryCodeStoreInterface;
use Infocyph\OTP\RecoveryCodes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\TestDox;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class RecoveryStoreContractTest extends TestCase
{
    /** @return array<string, array{array<string, mixed>}> */
    public static function consumptionCases(): array
    {
        return [
    'consumed is not boolean' => [['consumed' => 1, 'total' => 1, 'remaining' => 0, 'lastUsedAt' => new DateTimeImmutable()]],
    'negative total' => [['consumed' => false, 'total' => -1, 'remaining' => 0, 'lastUsedAt' => null]],
    'negative remaining' => [['consumed' => false, 'total' => 1, 'remaining' => -1, 'lastUsedAt' => null]],
    'remaining exceeds total' => [['consumed' => false, 'total' => 1, 'remaining' => 2, 'lastUsedAt' => null]],
    'last use is wrong type' => [['consumed' => false, 'total' => 1, 'remaining' => 1, 'lastUsedAt' => 'now']],
    'successful consume lacks timestamp' => [['consumed' => true, 'total' => 1, 'remaining' => 0, 'lastUsedAt' => null]],
        ];
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function replacementCases(): array
    {
        return [
    'wrong total' => [['total' => 3, 'remaining' => 3, 'lastUsedAt' => null]],
    'wrong remaining' => [['total' => 2, 'remaining' => 1, 'lastUsedAt' => null]],
    'stale last use' => [['total' => 2, 'remaining' => 2, 'lastUsedAt' => new DateTimeImmutable()]],
        ];
    }

    /** @param array<string, mixed> $state */
    #[DataProvider('consumptionCases')]
    #[TestDox('recovery codes reject impossible custom-store consumption state')]
    public function testInvalidConsumptionState(array $state): void
    {
        $store = $this->createMock(RecoveryCodeStoreInterface::class);
        $store->expects($this->once())->method('consume')->willReturnCallback(
            static function (string $binding, string $hashedCode, DateTimeImmutable $usedAt) use ($state): array {
                expect($binding)->toBe('user-1')
                    ->and($hashedCode)->toMatch('/^[a-f0-9]{64}$/')
                    ->and($usedAt->getTimestamp())->toBeGreaterThan(0);

                return $state;
            },
        );
        expect(fn () => (new RecoveryCodes($store, str_repeat('r', 32)))
            ->consume('user-1', 'ABCD-EFGH'))->toThrow(RuntimeException::class);
    }

    /** @param array<string, mixed> $state */
    #[DataProvider('replacementCases')]
    #[TestDox('recovery codes reject impossible custom-store replacement state')]
    public function testInvalidReplacementState(array $state): void
    {
        $store = $this->createMock(RecoveryCodeStoreInterface::class);
        $store->expects($this->once())->method('replace')->willReturnCallback(
            static function (string $binding, array $hashedCodes, DateTimeImmutable $issuedAt) use ($state): array {
                expect($binding)->toBe('user-1')
                    ->and($hashedCodes)->toHaveCount(2)
                    ->and($issuedAt->getTimestamp())->toBeGreaterThan(0);

                return $state;
            },
        );
        expect(fn () => (new RecoveryCodes($store, str_repeat('r', 32)))
            ->generate('user-1', count: 2))->toThrow(RuntimeException::class, 'invalid replacement state');
    }
}
