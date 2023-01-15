<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Http\Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class Response
{
    use WrapsMessage;

    protected ?Factory $factory = null;

    public function __construct(
        protected ResponseInterface $psr7,
        StreamInterface|Factory|null $streamOrFactory = null,
    ) {
        if ($streamOrFactory) {
            if ($streamOrFactory instanceof Factory) {
                $this->factory = $streamOrFactory;
            } else {
                $this->psr7 = $psr7->withBody($streamOrFactory);
            }
        }
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

    public function status(int $statusCode, ?string $reasonPhrase = null): static
    {
        if (empty($reasonPhrase)) {
            $this->psr7 = $this->psr7->withStatus($statusCode);
        } else {
            $this->psr7 = $this->psr7->withStatus($statusCode, $reasonPhrase);
        }

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

    public function body(StreamInterface|string $body): static
    {
        if ($body instanceof StreamInterface) {
            $this->psr7 = $this->psr7->withBody($body);

            return $this;
        }

        if ($this->factory) {
            $this->psr7 = $this->psr7->withBody($this->factory->stream($body));

            return $this;
        }

        throw new RuntimeException('No factory instance set in response object');
    }

    public function getBody(): StreamInterface
    {
        return $this->psr7->getBody();
    }

    public function write(string $content): static
    {
        $this->psr7->getBody()->write($content);

        return $this;
    }

    public function redirect(string $url, int $code = 302): static
    {
        $this->header('Location', $url);
        $this->status($code);

        return $this;
    }
}
