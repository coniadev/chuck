<?php

declare(strict_types=1);

namespace Chuck\Response;


interface ResponseFactoryInterface
{
    public function make(
        ?string $body = null,
        int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ): ResponseInterface;
}
