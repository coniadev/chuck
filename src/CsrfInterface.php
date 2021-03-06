<?php

declare(strict_types=1);

namespace Conia\Chuck;

interface CsrfInterface
{
    public function get(string $page = 'default'): ?string;
    public function verify(string $page = 'default', string $token = null): bool;
}
