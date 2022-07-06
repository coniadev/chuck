<?php

declare(strict_types=1);

namespace Conia\Chuck\Response;


class Response implements ResponseInterface
{
    public readonly Headers $headers;
    protected string $charset = 'UTF-8';
    protected string $protocol = '1.1';
    protected ?string $reasonPhrase = null;

    public function __construct(
        protected mixed $body = null,
        protected int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
    ) {
        $this->headers = new Headers($headers);
    }

    public function statusCode(int $statusCode, ?string $reasonPhrase = null): static
    {
        $this->statusCode = $statusCode;

        if ($reasonPhrase !== null) {
            $this->reasonPhrase = $reasonPhrase;
        }

        return $this;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    public function charset(string $charset): static
    {
        $this->charset = $charset;

        return $this;
    }

    public function protocol(string $protocol): static
    {
        $this->protocol = $protocol;

        return $this;
    }

    public function header(string $name, string $value, bool $replace = true): static
    {
        $this->headers->add($name, $value, $replace);

        return $this;
    }

    public function headers(): Headers
    {
        return $this->headers;
    }

    public function body(string $body): static
    {
        $this->body = $body;

        return $this;
    }

    public function getBody(): ?string
    {
        return $this->body;
    }

    public function emit(): void
    {
        $this->headers->emit(
            $this->statusCode,
            $this->protocol,
            $this->charset,
            $this->reasonPhrase
        );

        if (strtoupper($_SERVER['REQUEST_METHOD']) === 'HEAD') {
            return;
        }

        $body = $this->getBody();
        if ($body !== null) {
            echo $body;
        }
    }
}
