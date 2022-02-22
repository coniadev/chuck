<?php

declare(strict_types=1);

namespace Chuck\Tests\Fix;

use Chuck\Request;


class TestControllerWithRequest
{
    public function __construct(protected Request $request)
    {
    }

    public function wrongReturnType(): array
    {
        return [];
    }

    public function requestOnly(): string
    {
        return $this->request::class;
    }

    public function routeParams(string $string, float $float, int $int): array
    {
        return [
            'string' => $string,
            'float' => $float,
            'int' => $int,
            'request' => $this->request::class,
        ];
    }
}
