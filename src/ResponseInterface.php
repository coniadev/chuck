<?php

declare(strict_types=1);

namespace Chuck;

interface ResponseInterface
{
    public function __construct(
        RequestInterface $request,
        int $statusCode = 200,
        string|Stream $body = '',
        array $headers = [],
        string $protocol = '1.1',
        ?string $reasonPhrase = null,
    );
    public function setStatusCode(int $statusCode, ?string $reasonPhrase = null): void;
    public function getStatusCode(): int;
    public function setProtocol(string $protocol): void;
    public function addHeader(string $name, string $value, bool $replace = true): void;
    public function headersList(): array;
    public function getBody(): string|Stream;
    public function setBody(string|Stream $body): void;
    public function emit(): void;
}
