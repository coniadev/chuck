<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Request;
use Chuck\Response\Response;


class TestController
{
    public function textView(): string
    {
        return 'success';
    }

    public function arrayView(): array
    {
        return ['success' => true];
    }

    public function middlewareView(Request $request): Response
    {
        return $request->response(' view');
    }

    public function routeParams(string $string, float $float, Request $request, int $int): array
    {
        return [
            'string' => $string,
            'float' => $float,
            'int' => $int,
            'request' => $request::class,
        ];
    }
}
