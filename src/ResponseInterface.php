<?php

declare(strict_types=1);

namespace Chuck;

interface ResponseInterface
{
    public function __construct(
        int $statusCode,
        mixed $body,
        array $headers,
        string $protocol,
        ?string $reasonPhrase,
    );
    public function setStatusCode(int $statusCode, ?string $reasonPhrase);
    public function getStatusCode(): int;
    public function setProtocol(string $protocol): void;
    public function addHeader(string $key, string $value);
    public function headersList(): array;
    public function getBody(): mixed;
    public function setBody(mixed $body): void;
    public function emit(): void;
}
