<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Request;
use Chuck\Response;


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
        $response = $request->response;
        $response->setBody($response->getBody() . ' view');
        return $response;
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
