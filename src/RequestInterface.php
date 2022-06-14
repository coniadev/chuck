<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Response\{ResponseFactoryInterface, ResponseInterface};
use Chuck\Routing\RouterInterface;


interface RequestInterface
{
    public function response(
        ?string $body = null,
        int $statusCode = 200,
        array $headers = [],
    ): ResponseFactoryInterface|ResponseInterface;
    public function config(): ConfigInterface;
    public function router(): RouterInterface;
    public function method(): string;
    public function addMethod(string $name, callable $callable): void;
}
