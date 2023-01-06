<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Fixtures;

use Conia\Chuck\Attribute\Render;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\ResponseFactory;
use Conia\Chuck\Response;

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

    public function middlewareView(Registry $registry): Response
    {
        return (new ResponseFactory($registry))->html(' view');
    }

    #[Render('text'), TestMiddleware1]
    public function attributedMiddlewareView(Registry $registry): Response
    {
        return (new ResponseFactory($registry))->html(' attribute-string');
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
