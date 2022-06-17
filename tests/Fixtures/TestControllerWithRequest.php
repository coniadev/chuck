<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Request;


class TestControllerWithRequest
{
    public function __construct(protected Request $request)
    {
    }

    public function wrongReturnType(): mixed
    {
        // This provokes a json_encode error
        return stream_context_create();
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
