<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Conia\Chuck\Exception\RuntimeException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Stringable;

abstract class AbstractFactory implements Factory
{
    protected ResponseFactoryInterface $responseFactory;
    protected StreamFactoryInterface $streamFactory;

    abstract public function request(): ServerRequestInterface;

    public function response(int $code = 200, string $reasonPhrase = ''): ResponseInterface
    {
        return $this->responseFactory->createResponse($code, $reasonPhrase);
    }

    public function stream(mixed $content = ''): StreamInterface
    {
        if (is_string($content) || $content instanceof Stringable) {
            return $this->streamFactory->createStream((string)$content);
        }

        if (is_resource($content)) {
            return $this->streamFactory->createStreamFromResource($content);
        }

        throw new RuntimeException('Only strings, Stringable or resources are allowed');
    }

    public function streamFromFile(string $filename, string $mode = 'r'): StreamInterface
    {
        return $this->streamFactory->createStreamFromFile($filename, $mode);
    }
}
