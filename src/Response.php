<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\StreamFactoryInterface;

class Response
{
    public function __construct(
        protected ResponseInterface $response,
        protected StreamFactoryInterface $streamFactory,
    ) {
    }

    public function statusCode(int $statusCode, ?string $reasonPhrase = null): static
    {
        if ($reasonPhrase === null) {
            $this->response = $this->response->withStatus($statusCode);
        } else {
            $this->response = $this->response->withStatus($statusCode, $reasonPhrase);
        }

        return $this;
    }

    public function psr7(): ResponseInterface
    {
        return $this->response;
    }

    public function setPsr7(ResponseInterface $response): void
    {
        $this->response = $response;
    }

    public function getStatusCode(): int
    {
        return $this->response->getStatusCode();
    }

    public function getReasonPhrase(): string
    {
        return $this->response->getReasonPhrase();
    }

    public function protocolVersion(string $protocol): static
    {
        $this->response = $this->response->withProtocolVersion($protocol);

        return $this;
    }

    public function getProtocolVersion(): string
    {
        return $this->response->getProtocolVersion();
    }

    public function header(string $name, string $value): static
    {
        $this->response = $this->response->withAddedHeader($name, $value);

        return $this;
    }

    public function removeHeader(string $name): static
    {
        $this->response = $this->response->withoutHeader($name);

        return $this;
    }

    public function headers(): array
    {
        return $this->response->getHeaders();
    }

    public function getHeader(string $name): array
    {
        return $this->response->getHeader($name);
    }

    public function hasHeader(string $name): bool
    {
        return $this->response->hasHeader($name);
    }

    /**
     * @param string|resource|StreamInterface|null $body
     */
    public function body(mixed $body): static
    {
        $this->response = $this->response->withBody($this->streamFactory->createStream($body));

        return $this;
    }

    public function getBody(): StreamInterface
    {
        return $this->response->getBody();
    }
}
