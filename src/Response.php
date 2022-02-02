<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpNotFound;

class Response implements ResponseInterface
{
    protected int $status = 200;
    protected $body;
    protected $file;
    protected ?string $renderer = null;
    protected array $headers = [];
    protected $config;

    public function __construct(
        RequestInterface $request,
        $body = null,
        string $renderer = null
    ) {
        $this->request = $request;
        $this->config = $request->config;
        $this->body = $body;

        if ($renderer !== null) {
            $this->renderer = $renderer;
        }
    }

    public function setStatus(int $status): void
    {
        $this->status = $status;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    public function addHeader(
        string $key,
        string $value,
        bool $replace = false,
        ?int $statusCode = null
    ): void {
        $this->headers[$key] = [
            'value' => $value,
            'replace' => $replace,
            'statusCode' => $statusCode,
        ];
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getRawBody()
    {
        return $this->body;
    }

    public function getBody(): ?string
    {
        $renderer = $this->renderer;
        $body = $this->body;

        if ($body === null) {
            if ($renderer === 'json') {
                return 'null';
            }

            return null;
        }

        if ($renderer === null) {
            // auto detect renderer
            if (is_iterable($body)) {
                $renderer = 'json';
            } elseif (is_string($body)) {
                $renderer = 'string';
            } else {
                return null;
            }
        }

        $r = explode(':', $renderer);
        $type = $r[0];
        $identifier = implode(':', array_slice($r, 1));

        $class = $this->request->config->get('renderer')[$type];
        $rendererObj = new $class($this->request, $body, $identifier);

        foreach ($rendererObj->headers() as $header) {
            $this->addHeader($header['name'], $header['value']);
        }

        return $rendererObj->render();
    }

    public function file($path)
    {
        $this->file = $path;

        try {
            $ext = strtolower(pathinfo($path)['extension']);
            $contentType = [
                'js' => 'application/javascript',
                'css' => 'text/css',
                'html' => 'text/html',
            ][$ext] ?? null;
        } catch (\Exception $e) {
            $contentType = null;
        }

        // Should be a binary file
        try {
            if (!$contentType) {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $contentType = finfo_file($finfo, $path);
            }
        } catch (\Exception $e) {
            throw new HttpNotFound($this->request);
        }

        $this->addHeader('Content-Type', $contentType);

        switch ($this->config->get('fileserver')) {
            case null:
                $finfo = finfo_open(FILEINFO_MIME_ENCODING);
                $this->addHeader('Content-Transfer-Encoding', finfo_file($finfo, $path));
                break;
            case 'apache':
                // apt install libapache2-mod-xsendfile
                // a2enmod xsendfile
                // Apache config:
                //    XSendFile On
                //    XSendFilePath "/path/to/files"
                $this->addHeader("X-Sendfile", $file);
                break;
            case 'nginx':
                // Nginx config
                //   location /path/to/files/ {
                //       internal;
                //           alias   /some/path/; # note the trailing slash
                //       }
                //   }
                $this->addHeader("X-Accel-Redirect", $file);
                break;
        }
    }

    public function respond(): void
    {
        http_response_code($this->status);

        $body = $this->getBody();

        foreach ($this->headers as $header => $value) {
            if ($value['statusCode'] !== null) {
                header(
                    "$header: " . $value['value'],
                    $value['replace'],
                    $value['statusCode']
                );
            } else {
                header("$header: " . $value['value'], $value['replace']);
            }
        }

        if ($body !== null) {
            echo $body;
        }

        if ($this->file && $this->config->get('fileserver') === null) {
            readfile($this->file);
        }
    }
}
