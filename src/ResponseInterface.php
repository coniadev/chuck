<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Body\Body;


interface ResponseInterface
{
    public function setStatusCode(int $statusCode, ?string $reasonPhrase = null): void;
    public function statusCode(): int;
    public function protocol(string $protocol): void;
    public function header(string $name, string $value, bool $replace = true): void;
    public function getHeaderList(): array;
    public function getBody(): ?Body;
    public function body(string|Body $body): void;
    public function emit(): void;
}
