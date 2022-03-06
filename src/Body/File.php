<?php

declare(strict_types=1);

namespace Chuck\Body;

use \finfo;
use \RuntimeException;
use \Throwable;
use Chuck\ResponseInterface;
use Chuck\Error\HttpNotFound;


class File implements Body
{
    protected bool $sendFile = false;

    public function __construct(
        protected ResponseInterface $response,
        protected string $file,
        protected int $chunkSize,
        protected bool $throwNotFound = true,
    ) {
        if (!is_file($file)) {
            if ($throwNotFound) {
                throw new HttpNotFound();
            }

            throw new RuntimeException('File for response body does not exist');
        }

        $contentType = mime_content_type($this->file) ?: null;

        // Should be a binary file
        try {
            if (!$contentType) {
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $contentType = finfo_file($finfo, $this->file);
            }
        } catch (Throwable) {
            $contentType = 'application/octet-stream';
        }

        $response->header('Content-Type', $contentType);
        $finfo = new finfo(FILEINFO_MIME_ENCODING);
        $response->header('Content-Transfer-Encoding', finfo_file($finfo, $file));
        $response->header('Content-Length', (string)filesize($this->file));
    }

    public function sendfile(): self
    {
        $this->sendFile = true;
        $server = strtolower($_SERVER['SERVER_SOFTWARE']);

        if (strpos($server, 'nginx') !== false) {
            $this->response->header('X-Accel-Redirect', $this->file);
        } else {
            $this->response->header('X-Sendfile', $this->file);
        }

        return $this;
    }

    public function download(): self
    {
        $this->response->header(
            'Content-Disposition',
            'attachment; filename="' . basename($this->file) . '"'
        );

        return $this;
    }

    public function emit(): void
    {
        if (!$this->sendFile) {
            // @codeCoverageIgnoreStart
            if (!(PHP_SAPI == 'cli')) {
                // Removes anything in the buffer, as this might corrupt the download
                ob_end_clean();
            }
            // @codeCoverageIgnoreEnd

            $stream = fopen($this->file, 'rb');

            while (!feof($stream)) {
                echo fread($stream, $this->chunkSize);
            }

            fclose($stream);
        }
    }
}
