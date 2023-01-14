<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Http\Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class Response
{
    use WrapsMessage;

    public function __construct(
        protected ResponseInterface $psr7,
        protected Factory $factory,
    ) {
    }

    public function status(int $statusCode, ?string $reasonPhrase = null): static
    {
        if (empty($reasonPhrase)) {
            $this->psr7 = $this->psr7->withStatus($statusCode);
        } else {
            $this->psr7 = $this->psr7->withStatus($statusCode, $reasonPhrase);
        }

        return $this;
    }

    public function psr7(): ResponseInterface
    {
        return $this->psr7;
    }

    public function setPsr7(ResponseInterface $psr7): static
    {
        $this->psr7 = $psr7;

        return $this;
    }

    public function getStatusCode(): int
    {
        return $this->psr7->getStatusCode();
    }

    public function getReasonPhrase(): string
    {
        return $this->psr7->getReasonPhrase();
    }

    public function protocolVersion(string $protocol): static
    {
        $this->psr7 = $this->psr7->withProtocolVersion($protocol);

        return $this;
    }

    public function header(string $name, string $value): static
    {
        $this->psr7 = $this->psr7->withAddedHeader($name, $value);

        return $this;
    }

    public function removeHeader(string $name): static
    {
        $this->psr7 = $this->psr7->withoutHeader($name);

        return $this;
    }

    public function headers(): array
    {
        return $this->psr7->getHeaders();
    }

    public function getHeader(string $name): array
    {
        return $this->psr7->getHeader($name);
    }

    public function hasHeader(string $name): bool
    {
        return $this->psr7->hasHeader($name);
    }

    public function body(mixed $body): static
    {
        $stream = $this->factory->stream($body);
        assert($stream instanceof StreamInterface);

        $this->psr7 = $this->psr7->withBody($stream);

        return $this;
    }

    public function getBody(): StreamInterface
    {
        return $this->psr7->getBody();
    }

    public function write(string $content): int
    {
        return $this->psr7->getBody()->write($content);
    }

    public function redirect(string $url, int $code = 302): static
    {
        $this->header('Location', $url);
        $this->status($code);

        return $this;
    }

    public function withStatus(int $code, string $reasonPhrase = ''): static
    {
        return $this->status($code, $reasonPhrase);
    }
}
