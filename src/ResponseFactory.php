<?php

declare(strict_types=1);

namespace Conia\Chuck;

use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\RuntimeException;
use Conia\Chuck\Json;
use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Response;
use finfo;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\StreamInterface as PsrStream;

class ResponseFactory
{
    public function __construct(protected Registry $registry)
    {
    }

    /**
     * @param null|PsrStream|resource|string $body
     */
    public function create(
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        return new Response($this->createPsrResponse($code, $reasonPhrase), $this->createHttpFactory());
    }

    /**
     * @param null|PsrStream|resource|string $body
     */
    public function html(
        mixed $body = null,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $psrResponse = $this->createPsrResponse($code, $reasonPhrase)->withAddedHeader(
            'Content-Type',
            'text/html'
        );

        if ($body) {
            $psrResponse = $psrResponse->withBody($this->createHttp($body));
        }

        return new Response($psrResponse, $this->createHttpFactory());
    }

    /**
     * @param null|PsrStream|resource|string $body
     */
    public function text(
        mixed $body = null,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $psrResponse = $this->createPsrResponse($code, $reasonPhrase)->withAddedHeader(
            'Content-Type',
            'text/plain'
        );

        if ($body) {
            $psrResponse = $psrResponse->withBody($this->createHttp($body));
        }

        return new Response($psrResponse, $this->createHttpFactory());
    }

    public function json(
        mixed $data,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $psrResponse = $this->createPsrResponse($code, $reasonPhrase)->withAddedHeader(
            'Content-Type',
            'application/json'
        );

        $psrResponse = $psrResponse->withBody($this->createHttp(Json::encode($data)));

        return new Response($psrResponse, $this->createHttpFactory());
    }

    public function file(
        string $file,
        bool $throwNotFound = true,
        int $code = 200,
        string $reasonPhrase = '',
    ): Response {
        $this->validateFile($file, $throwNotFound);

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $contentType = $finfo->file($file);
        $finfo = new finfo(FILEINFO_MIME_ENCODING);
        $encoding = $finfo->file($file);

        $psrResponse = $this->createPsrResponse($code, $reasonPhrase)
            ->withAddedHeader('Content-Type', $contentType)
            ->withAddedHeader('Content-Transfer-Encoding', $encoding);

        $stream = $this->createHttpFactory()->streamFromFile($file, 'rb');
        $size = $stream->getSize();

        if (!is_null($size)) {
            $psrResponse = $psrResponse->withAddedHeader('Content-Length', (string)$size);
        }

        return new Response($psrResponse->withBody($stream), $this->createHttpFactory());
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
        $psrResponse = $this->createPsrResponse($code, $reasonPhrase);

        if (strpos($server, 'nginx') !== false) {
            $psrResponse = $psrResponse->withAddedHeader('X-Accel-Redirect', $file);
        } else {
            $psrResponse = $psrResponse->withAddedHeader('X-Sendfile', $file);
        }

        return new Response($psrResponse, $this->createHttpFactory());
    }

    protected function createPsrResponse(
        int $code = 200,
        string $reasonPhrase = ''
    ): PsrResponse {
        $response = $this->createHttpFactory()->response($code, $reasonPhrase);
        assert($response instanceof PsrResponse);

        return $response;
    }

    protected function createHttpFactory(): Factory
    {
        $factory = $this->registry->get(Factory::class);
        assert($factory instanceof Factory);

        return $factory;
    }

    protected function createHttp(mixed $body): PsrStream
    {
        $factory = $this->createHttpFactory();
        $stream = $factory->stream($body);
        assert($stream instanceof PsrStream);

        return $stream;
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
}
