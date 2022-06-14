<?php

declare(strict_types=1);

namespace Chuck\Response;


interface ResponseInterface
{
    public function statusCode(int $statusCode, ?string $reasonPhrase = null): self;
    public function getStatusCode(): int;
    public function protocol(string $protocol): self;
    public function header(string $name, string $value, bool $replace = true): self;
    public function body(string $body): self;
    public function getBody(): ?string;
    public function emit(): void;
}
