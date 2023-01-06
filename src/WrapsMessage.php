<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Psr\Http\Message\StreamInterface;

trait WrapsMessage
{
    public function getProtocolVersion(): string
    {
        return $this->psr7->getProtocolVersion();
    }

    public function withProtocolVersion(string $version): static
    {
        $this->psr7 = $this->psr7->withProtocolVersion($version);

        return $this;
    }

    public function getHeaders(): array
    {
        return $this->psr7->getHeaders();
    }

    public function hasHeader(string $header): bool
    {
        return $this->psr7->hasHeader($header);
    }

    public function getHeader($header): array
    {
        return $this->psr7->getHeader($header);
    }

    public function getHeaderLine(string $header): string
    {
        return $this->psr7->getHeaderLine($header);
    }

    public function withHeader(string $header, string $value): static
    {
        $this->psr7 = $this->psr7->withHeader($header, $value);

        return $this;
    }

    public function withAddedHeader(string $header, string $value): static
    {
        $this->psr7 = $this->psr7->withAddedHeader($header, $value);

        return $this;
    }

    public function withoutHeader(string $header): static
    {
        $this->psr7 = $this->psr7->withoutHeader($header);

        return $this;
    }

    public function getBody(): StreamInterface
    {
        return $this->psr7->getBody();
    }

    public function withBody(StreamInterface $body): static
    {
        $this->psr7 = $this->psr7->withBody($body);

        return $this;
    }
}
