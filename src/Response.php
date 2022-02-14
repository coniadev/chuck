<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpNotFound;

const REASON_PHRASES = [
    100 => 'Continue', 101 => 'Switching Protocols',
    200 => 'OK', 201 => 'Created', 202 => 'Accepted', 203 => 'Non-Authoritative Information',
    204 => 'No Content', 205 => 'Reset Content', 206 => 'Partial Content',
    300 => 'Multiple Choices', 301 => 'Moved Permanently', 302 => 'Found', 303 => 'See Other',
    304 => 'Not Modified', 305 => 'Use Proxy', 307 => 'Temporary Redirect',
    400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 403 => 'Forbidden',
    404 => 'Not Found', 405 => 'Method Not Allowed', 406 => 'Not Acceptable',
    407 => 'Proxy Authentication Required', 408 => 'Request Time-out', 409 => 'Conflict',
    410 => 'Gone', 411 => 'Length Required', 412 => 'Precondition Failed',
    413 => 'Request Entity Too Large', 414 => 'Request-URI Too Large', 415 => 'Unsupported Media Type',
    416 => 'Requested range not satisfiable', 417 => 'Expectation Failed',
    500 => 'Internal Server Error', 501 => 'Not Implemented', 502 => 'Bad Gateway',
    503 => 'Service Unavailable', 504 => 'Gateway Time-out', 505 => 'HTTP Version not supported',
];


class Response implements ResponseInterface
{
    protected $file;
    protected $headersList = [];

    public function __construct(
        protected int $statusCode = 200,
        protected mixed $body = null,
        protected array $headers = [],
        protected string $protocol = '1.1',
        protected ?string $reasonPhrase = null,
    ) {
        if ($reasonPhrase && $statusCode === null) {
            throw new \InvalidArgumentException('$statusCode must not be null if $reasonPhrase is set');
        }
    }

    public function setStatusCode(int $statusCode, ?string $reasonPhrase = null): void
    {
        $this->statusCode = $statusCode;

        if ($reasonPhrase !== null) {
            $this->reasonPhrase = $reasonPhrase;
        }
    }

    public function setProtocol(string $protocol): void
    {
        $this->protocol = $protocol;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    protected function validateHeaderName(string $name): void
    {
        if (preg_match("/^[0-9A-Za-z-]+$/", $name) !== 1) {
            throw new \InvalidArgumentException(
                'Header name must consist only of the characters a-zA-Z0-9 and -.'
            );
        }
    }

    public function addHeader(
        string $name,
        string $value,
        bool $replace = true,
    ): void {
        $this->validateHeaderName($name);
        $name = ucwords(strtolower($name, '-'));

        if (array_key_exists($name, $this->headers) && $replace === false) {
            $this->headers[$name] = [
                'value' => array_merge($this->header[$name]['value'], $value),
                'replace' => $replace,
            ];
        }

        $this->headers[$name] = [
            'value' => [$value],
            'replace' => $replace,
        ];
    }

    public function headersList(): array
    {
        return $this->headersList;
    }

    public function getBody(): mixed
    {
        return $this->body;
    }

    public function setBody(mixed $body): void
    {
        $this->body = $body;
    }

    protected function header(string $value, bool $replace): void
    {
        if (PHP_SAPI === 'cli') {
            $this->headersList[] = $value;
        } else {
            header($value, $replace);
        }
    }

    public function file(string $path): void
    {
        $this->file = $path;

        try {
            $ext = strtolower(pathinfo($path)['extension']);
            $contentType = [
                'js' => 'application/javascript',
                'css' => 'text/css',
                'html' => 'text/html',
            ][$ext] ?? null;
        } catch (\Exception) {
            $contentType = null;
        }

        // Should be a binary file
        try {
            if (!$contentType) {
                $finfo = new \finfo(FILEINFO_MIME_TYPE);
                $contentType = finfo_file($finfo, $path);
            }
        } catch (\Exception) {
            throw new HttpNotFound($this->request);
        }

        $this->addHeader('Content-Type', $contentType);
        $finfo = new \finfo(FILEINFO_MIME_ENCODING);
        $this->addHeader('Content-Transfer-Encoding', finfo_file($finfo, $path));
    }

    public function emit(): void
    {
        $body = $this->getBody();

        // Fix Content-Type
        $ct = $this->headers['Content-Type']['value'][0] ?? null;
        if (!array_key_exists('Content-Type', $this->headers)) {
            $this->header('Content-Type: text/html; charset=UTF-8', true);
        } else {
            $ct = $this->headers['Content-Type']['value'][0];

            if (stripos($ct, 'text/') === 0 && stripos($ct, 'charset') === false) {
                // Add missing charset
                $this->headers['Content-Type']['value'][0] .= '; charset=UTF-8';
            }
        }

        foreach ($this->headers as $header) {
            foreach ($header as $value) {
                $this->header(sprintf('%s: %s', $header['name'], $value), $header['replace']);
            }
        }

        // Emit status line after general headers to overwrite previous status codes
        $this->header(sprintf(
            'HTTP/%s %d%s',
            $this->protocol,
            $this->statusCode,
            $this->reasonPhrase ? ' ' . $this->reasonPhrase : ''
        ), true);

        if ($body !== null) {
            echo $body;
        }

        if ($this->file && $this->config->get('fileserver') === null) {
            readfile($this->file);
        }
    }
}
