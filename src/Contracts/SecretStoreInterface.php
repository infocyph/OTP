<?php

declare(strict_types=1);

namespace Infocyph\OTP\Contracts;

interface SecretStoreInterface
{
    public function delete(string $binding): void;

    public function get(string $binding): ?string;

    public function put(string $binding, string $secret): void;
}
