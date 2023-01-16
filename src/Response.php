<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Http\WrapsMessage;
use Conia\Chuck\Psr\Factory;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\StreamInterface as PsrStream;

class Response
{
    use WrapsMessage;

    protected ?Factory $factory = null;

    public function __construct(
        protected PsrResponse $psr,
        PsrStream|Factory|null $streamOrFactory = null,
    ) {
        if ($streamOrFactory) {
            if ($streamOrFactory instanceof Factory) {
                $this->factory = $streamOrFactory;
            } else {
                $this->psr = $psr->withBody($streamOrFactory);
            }
        }
    }

    public function psr(): PsrResponse
    {
        return $this->psr;
    }

    public function setPsr(PsrResponse $psr): static
    {
        $this->psr = $psr;

        return $this;
    }

    public function status(int $statusCode, ?string $reasonPhrase = null): static
    {
        if (empty($reasonPhrase)) {
            $this->psr = $this->psr->withStatus($statusCode);
        } else {
            $this->psr = $this->psr->withStatus($statusCode, $reasonPhrase);
        }

        return $this;
    }

    public function getStatusCode(): int
    {
        return $this->psr->getStatusCode();
    }

    public function getReasonPhrase(): string
    {
        return $this->psr->getReasonPhrase();
    }

    public function protocolVersion(string $protocol): static
    {
        $this->psr = $this->psr->withProtocolVersion($protocol);

        return $this;
    }

    public function header(string $name, string $value): static
    {
        $this->psr = $this->psr->withAddedHeader($name, $value);

        return $this;
    }

    public function removeHeader(string $name): static
    {
        $this->psr = $this->psr->withoutHeader($name);

        return $this;
    }

    public function headers(): array
    {
        return $this->psr->getHeaders();
    }

    public function getHeader(string $name): array
    {
        return $this->psr->getHeader($name);
    }

    public function hasHeader(string $name): bool
    {
        return $this->psr->hasHeader($name);
    }

    public function body(PsrStream|string $body): static
    {
        if ($body instanceof PsrStream) {
            $this->psr = $this->psr->withBody($body);

            return $this;
        }

        if ($this->factory) {
            $this->psr = $this->psr->withBody($this->factory->stream($body));

            return $this;
        }

        throw new RuntimeException('No factory instance set in response object');
    }

    public function getBody(): PsrStream
    {
        return $this->psr->getBody();
    }

    public function write(string $content): static
    {
        $this->psr->getBody()->write($content);

        return $this;
    }

    public function redirect(string $url, int $code = 302): static
    {
        $this->header('Location', $url);
        $this->status($code);

        return $this;
    }
}
