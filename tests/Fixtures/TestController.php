<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Factory;
use Conia\Chuck\Renderer\Render;
use Conia\Chuck\Request;
use Conia\Chuck\Response;

class TestController
{
    #[TestAttribute, Render('text')]
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

    public function middlewareView(Factory $factory): Response
    {
        return Response::fromFactory($factory)->html(' view');
    }

    #[Render('text'), TestMiddleware1]
    public function attributedMiddlewareView(Factory $factory): Response
    {
        $s = ' attribute-string';

        return Response::fromFactory($factory)->html($s);
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
