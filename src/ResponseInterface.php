<?php

declare(strict_types=1);

namespace Chuck;

interface ResponseInterface
{
    public function __construct(Request $request, $body);
    public function setStatusCode(int $statusCode, ?string $reasonPhrase);
    public function setProtocol(string $protocol);
    public function addHeader(string $key, string $value);
    public function getBody(): ?mixed;
    public function setBody(mixed $body): void;
    public function emit(): void;
}
