<?php

declare(strict_types=1);

namespace Conia\Chuck\Response;

interface ResponseInterface
{
    public function statusCode(int $statusCode, ?string $reasonPhrase = null): static;
    public function getStatusCode(): int;
    public function protocol(string $protocol): static;
    public function header(string $name, string $value, bool $replace = true): static;
    public function headers(): Headers;
    public function body(string $body): static;
    public function getBody(): ?string;
    public function emit(): void;
}
