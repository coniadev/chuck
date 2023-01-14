<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Conia\Chuck\Exception\RuntimeException;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\ServerRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Stringable;
use Throwable;

class Guzzle implements Factory
{
    protected HttpFactory $factory;

    public function __construct()
    {
        try {
            $this->factory = new HttpFactory();
            // @codeCoverageIgnoreStart
        } catch (Throwable) {
            throw new RuntimeException('Install guzzlehttp/psr7');
            // @codeCoverageIgnoreEnd
        }
    }

    public function request(): ServerRequestInterface
    {
        return ServerRequest::fromGlobals();
    }

    public function response(int $code = 200, string $reasonPhrase = ''): ResponseInterface
    {
        return $this->factory->createResponse($code, $reasonPhrase);
    }

    public function stream(mixed $content = ''): StreamInterface
    {
        if (is_string($content) || $content instanceof Stringable) {
            return $this->factory->createStream((string)$content);
        }

        if (is_resource($content)) {
            return $this->factory->createStreamFromResource($content);
        }

        throw new RuntimeException('Only strings, Stringable or resources are allowed');
    }

    public function streamFromFile(string $filename, string $mode = 'r'): StreamInterface
    {
        return $this->factory->createStreamFromFile($filename, $mode);
    }
}
