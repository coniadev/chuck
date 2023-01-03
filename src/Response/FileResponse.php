<?php

declare(strict_types=1);

namespace Conia\Chuck\Response;

use finfo;
use Conia\Chuck\Exception\HttpNotFound;
use Conia\Chuck\Exception\LogicException;
use Conia\Chuck\Exception\RuntimeException;

class FileResponse extends Response
{
    protected bool $sendFile = false;

    public function __construct(
        protected string $file,
        protected int $statusCode = 200,
        /** @param list<array{name: string, value: string, replace: bool}> */
        array $headers = [],
        protected int $chunkSize = 2 << 20, // 2 MB
        protected bool $throwNotFound = true,
    ) {
        parent::__construct(null, $statusCode, $headers);

        if (!is_file($file)) {
            if ($throwNotFound) {
                throw new HttpNotFound();
            }

            throw new RuntimeException('File not found');
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $contentType = finfo_file($finfo, $this->file);

        $this->header('Content-Type', $contentType);
        $finfo = new finfo(FILEINFO_MIME_ENCODING);
        $this->header('Content-Transfer-Encoding', finfo_file($finfo, $file));
        $this->header('Content-Length', (string)filesize($this->file));
    }

    public function sendfile(): static
    {
        $this->sendFile = true;
        $server = strtolower($_SERVER['SERVER_SOFTWARE'] ?? '');

        if (strpos($server, 'nginx') !== false) {
            $this->header('X-Accel-Redirect', $this->file);
        } else {
            $this->header('X-Sendfile', $this->file);
        }

        return $this;
    }

    public function download(): static
    {
        $this->header(
            'Content-Disposition',
            'attachment; filename="' . basename($this->file) . '"'
        );

        return $this;
    }

    public function body(string $body): static
    {
        throw new LogicException('The body cannot be set on a FileResponse instance.');
    }

    public function emit(bool $cleanOutputBuffer = true): void
    {
        parent::emit();

        if (!$this->sendFile) {
            if ($cleanOutputBuffer) {
                // ob_end_clean will be called in the test suite
                // @codeCoverageIgnoreStart
                // Removes anything in the buffer, as this might corrupt the download
                ob_end_clean();
                // @codeCoverageIgnoreEnd
            }

            $stream = fopen($this->file, 'rb');

            while (!feof($stream)) {
                echo fread($stream, $this->chunkSize);
            }

            fclose($stream);
        }
    }
}
