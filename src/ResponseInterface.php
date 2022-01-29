<?php

declare(strict_types=1);

namespace Chuck;

interface ResponseInterface
{
    public function __construct(Request $request, $body);
    public function setStatus(int $status);
    public function addHeader(string $key, string $value);
    public function getRawBody();
    public function getBody(): ?string;
    public function respond();
}
