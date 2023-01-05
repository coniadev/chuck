<?php

declare(strict_types=1);

namespace Conia\Chuck;

use finfo;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Registry;
use Conia\Chuck\Response;
use Conia\Chuck\Util\Json;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;

class ResponseFactory
{
    public function __construct(protected Registry $registry)
    {
    }

    protected function createPsr7Response(
        int $code = 200,
        string $reasonPhrase = ''
    ): ResponseInterface {
        $psr7Factory = $this->registry->resolve(ResponseFactoryInterface::class);

        return $psr7Factory->createResponse($code, $reasonPhrase);
    }

    protected function createPsr7StreamFactory(): StreamFactoryInterface
    {
        return $this->registry->resolve(StreamFactoryInterface::class);
    }

    protected function createPsr7Stream(mixed $body): StreamInterface
    {
        $psr7Factory = $this->createPsr7StreamFactory();

        return $psr7Factory->createStream($body);
    }

    /**
     * @param string|resource|StreamInterface|null $body
     */
    public function create(
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        return new Response($this->createPsr7Response($code, $reasonPhrase), $this->createPsr7StreamFactory());
    }

    /**
     * @param string|resource|StreamInterface|null $body
     */
    public function html(
        mixed $body = null,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $psr7Response = $this->createPsr7Response($code, $reasonPhrase)->withAddedHeader(
            'Content-Type',
            'text/html'
        );

        if ($body) {
            $psr7Response = $psr7Response->withBody($this->createPsr7Stream($body));
        }

        return new Response($psr7Response, $this->createPsr7StreamFactory());
    }

    /**
     * @param string|resource|StreamInterface|null $body
     */
    public function text(
        mixed $body = null,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $psr7Response = $this->createPsr7Response($code, $reasonPhrase)->withAddedHeader(
            'Content-Type',
            'text/plain'
        );

        if ($body) {
            $psr7Response = $psr7Response->withBody($this->createPsr7Stream($body));
        }

        return new Response($psr7Response, $this->createPsr7StreamFactory());
    }

    public function json(
        mixed $data,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $psr7Response = $this->createPsr7Response($code, $reasonPhrase)->withAddedHeader(
            'Content-Type',
            'application/json'
        );

        $psr7Response = $psr7Response->withBody($this->createPsr7Stream(Json::encode($data)));

        return new Response($psr7Response, $this->createPsr7StreamFactory());
    }

    protected function validateFile(string $file, bool $throwNotFound): void
    {
        if (!is_file($file)) {
            if ($throwNotFound) {
                throw new HttpNotFound();
            }

            throw new RuntimeException('File not found');
        }
    }

    public function file(
        string $file,
        bool $throwNotFound = true,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $this->validateFile($file, $throwNotFound);

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $contentType = finfo_file($finfo, $file);
        $finfo = new finfo(FILEINFO_MIME_ENCODING);
        $encoding = finfo_file($finfo, $file);

        $psr7Response = $this->createPsr7Response($code, $reasonPhrase)
            ->withAddedHeader('Content-Type', $contentType)
            ->withAddedHeader('Content-Transfer-Encoding', $encoding);

        $stream = $this->createPsr7StreamFactory()->createStreamFromFile($file, 'rb');
        $size = $stream->getSize();

        if (!is_null($size)) {
            $psr7Response = $psr7Response->withAddedHeader('Content-Length', (string)$size);
        }

        return new Response($psr7Response->withBody($stream), $this->createPsr7StreamFactory());
    }

    public function download(
        string $file,
        string $newName = '',
        bool $throwNotFound = true,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $response = $this->file($file, $throwNotFound, $code, $reasonPhrase);
        $response->header(
            'Content-Disposition',
            'attachment; filename="' . ($newName ?: basename($file)) . '"'
        );

        return $response;
    }

    public function sendfile(
        string $file,
        bool $throwNotFound = true,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $this->validateFile($file, $throwNotFound);
        $server = strtolower($_SERVER['SERVER_SOFTWARE'] ?? '');
        $psr7Response = $this->createPsr7Response($code, $reasonPhrase);

        if (strpos($server, 'nginx') !== false) {
            $psr7Response = $psr7Response->withAddedHeader('X-Accel-Redirect', $file);
        } else {
            $psr7Response = $psr7Response->withAddedHeader('X-Sendfile', $file);
        }

        return new Response($psr7Response, $this->createPsr7StreamFactory());
    }
}
