<?php

declare(strict_types=1);

namespace Chuck\Tests\Fixtures;

use Chuck\Attribute\Render;
use Chuck\Request;
use Chuck\Response\Response;


class TestController
{
    #[TestAttribute]
    public function textView(): string
    {
        return 'text';
    }

    public function stringableView(): TestClass
    {
        return new TestClass();
    }

    #[TestAttribute, TestAttributeExt, TestAttributeDiff]
    public function arrayView(): array
    {
        return ['success' => true];
    }

    public function middlewareView(Request $request): Response
    {
        return $request->response->html(' view');
    }

    #[Render('text'), TestMiddleware1]
    public function attributedMiddlewareView(Request $request): Response
    {
        return new Response(' ' . $request->test());
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

    public function routeDefaultValueParams(string $string, int $int = 13): array
    {
        return [
            'string' => $string,
            'int' => $int,
        ];
    }
}
