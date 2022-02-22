<?php

declare(strict_types=1);

namespace Chuck\Body;

use Chuck\ResponseInterface;
use Chuck\Error\HttpNotFound;


class File implements Body
{
    public function __construct(
        protected ResponseInterface $response,
        protected string $file,
        protected bool $sendFile,
        protected bool $asDownload,
        protected int $chunkSize,
    ) {
        if (!is_file($file)) {
            throw new HttpNotFound();
        }

        $contentType = mime_content_type($this->file) ?: null;

        // Should be a binary file
        try {
            if (!$contentType) {
                $finfo = new \finfo(FILEINFO_MIME_TYPE);
                $contentType = finfo_file($finfo, $this->file);
            }
        } catch (\Exception) {
            throw new HttpNotFound();
        }

        $response->addHeader('Content-Type', $contentType);
        $finfo = new \finfo(FILEINFO_MIME_ENCODING);
        $response->addHeader('Content-Transfer-Encoding', finfo_file($finfo, $file));
        $response->addHeader('Content-Size', (string)filesize($this->file));

        if ($sendFile) {
            $server = strtolower($_SERVER['SERVER_SOFTWARE']);

            if (strpos($server, 'nginx') !== false) {
            } else {
            }
        }
    }

    public function emit(): void
    {
        if (!$this->sendFile) {
            // Removes anything in the buffer, as this might corrupt the download
            ob_end_clean();

            $stream = fopen($this->file, 'rb');

            while (!feof($stream)) {
                echo fread($stream, $this->chunkSize);
            }

            fclose($stream);
        }
    }
}
