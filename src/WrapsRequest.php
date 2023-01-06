<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Psr\Http\Message\UriInterface;

trait WrapsRequest
{
    public function getServerParams(): array
    {
        return $this->psr7->getServerParams();
    }

    public function withMethod(string $method): static
    {
        $this->psr7 = $this->psr7->withMethod($method);

        return $this;
    }

    public function getMethod(): string
    {
        return $this->psr7->getMethod();
    }

    public function withRequestTarget(string $requestTarget): static
    {
        $this->psr7 = $this->psr7->withRequestTarget($requestTarget);

        return $this;
    }

    public function getRequestTarget(): string
    {
        return $this->psr7->getRequestTarget();
    }

    public function withQueryParams(array $query): static
    {
        $this->psr7 = $this->psr7->withQueryParams($query);

        return $this;
    }

    public function getQueryParams(): array
    {
        return $this->psr7->getQueryParams();
    }

    public function withParsedBody(null|array|object $data): static
    {
        $this->psr7 = $this->psr7->withParsedBody($data);

        return $this;
    }

    public function getParsedBody(): null|array|object
    {
        return $this->psr7->getParsedBody();
    }

    public function withCookieParams(array $cookies): static
    {
        $this->psr7 = $this->psr7->withCookieParams($cookies);

        return $this;
    }

    public function getCookieParams(): array
    {
        return $this->psr7->getCookieParams();
    }

    public function withUploadedFiles(array $uploadedFiles): static
    {
        $this->psr7 = $this->psr7->withUploadedFiles($uploadedFiles);

        return $this;
    }

    public function getUploadedFiles(): array
    {
        return $this->psr7->getUploadedFiles();
    }

    public function withUri(UriInterface $uri, bool $preserveHost = false): static
    {
        $this->psr7 = $this->psr7->withUri($uri, $preserveHost);

        return $this;
    }

    public function getUri(): UriInterface
    {
        return $this->psr7->getUri();
    }

    public function withAttribute(string $attribute, mixed $value): static
    {
        $this->psr7 = $this->psr7->withAttribute($attribute, $value);

        return $this;
    }

    public function withoutAttribute(string $attribute): static
    {
        $this->psr7 = $this->psr7->withoutAttribute($attribute);

        return $this;
    }

    public function getAttributes(): array
    {
        return $this->psr7->getAttributes();
    }

    public function getAttribute(string $attribute, mixed $default = null): mixed
    {
        return $this->psr7->getAttribute($attribute, $default);
    }
}
