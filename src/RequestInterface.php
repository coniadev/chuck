<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Routing\RouterInterface;


interface RequestInterface
{
    public function getResponse(
        int $statusCode = 200,
        mixed $body = null,
        array $headers = [],
        ?string $protocol = null,
        ?string $reasonPhrase = null,
    ): ResponseInterface;
    public function getConfig(): ConfigInterface;
    public function getRouter(): RouterInterface;
    public function method(): string;
    public function addMethod(string $name, callable $callable): void;
}
