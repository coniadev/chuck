<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Body\Body;


interface ResponseInterface
{
    public function setStatusCode(int $statusCode, ?string $reasonPhrase = null): void;
    public function getStatusCode(): int;
    public function setProtocol(string $protocol): void;
    public function addHeader(string $name, string $value, bool $replace = true): void;
    public function headersList(): array;
    public function getBody(): ?Body;
    public function setBody(string|Body $body): void;
    public function emit(): void;
}
