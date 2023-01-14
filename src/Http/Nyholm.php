<?php

declare(strict_types=1);

namespace Conia\Chuck\Http;

use Conia\Chuck\Exception\RuntimeException;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Stringable;
use Throwable;

class Nyholm implements Factory
{
    protected Psr17Factory $factory;

    public function __construct()
    {
        try {
            $this->factory = new Psr17Factory();
            // @codeCoverageIgnoreStart
        } catch (Throwable) {
            throw new RuntimeException('Install nyholm/psr7-server');
            // @codeCoverageIgnoreEnd
        }
    }

    public function request(): ServerRequestInterface
    {
        $creator = new ServerRequestCreator(
            $this->factory, // ServerRequestFactory
            $this->factory, // UriFactory
            $this->factory, // UploadedFileFactory
            $this->factory  // StreamFactory
        );

        return $creator->fromGlobals();
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
