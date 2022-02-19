<?php

declare(strict_types=1);

namespace Chuck;

use \ValueError;
use Chuck\Util\Path;


class Template implements TemplateInterface
{
    protected RequestInterface $request;
    protected array $folders = [];
    protected Path $pathUtil;

    public function __construct(
        RequestInterface $request,
        protected array $defaults = [],
    ) {
        $this->request = $request;
        $config = $request->getConfig();

        $this->pathUtil = new Path($config);
        $this->addFolders($config->templates());
    }

    protected function addFolders(array $folders): void
    {
        foreach ($folders as $key => $dir) {
            if (!$this->pathUtil->insideRoot($dir)) {
                throw new ValueError("Template paths is not inside the project root directory: $dir");
            }

            if (!is_dir($dir)) {
                throw new ValueError("Template directory does not exists: $dir");
            }

            $this->folders[$key] = $dir;
        }
    }

    public function render(string $template, array $context = []): string
    {
        $context = array_merge($this->defaults, $context);
        $error = null;
        $path = $this->getPath($template);

        ob_start();

        try {
            $this->load($path, $context);
        } catch (\Throwable $e) {
            $error = $e;
        }

        $content = ob_get_contents();
        ob_end_clean();

        if ($error === null) {
            return $content;
        }

        throw $error;
    }

    protected function getPath(string $template): string
    {
        try {
            [$namespace, $file] = explode('::', $template);

            if (empty($namespace) || empty($file)) {
                throw new ValueError("Invalid template format: '$template'. Use 'namespace::template/path'.");
            }
        } catch (\Throwable) {
            throw new ValueError("Invalid template format: '$template'. Use 'namespace::template/path'.");
        }

        $file = trim(strtr($file, '\\', '/'), '/');

        $ds = DIRECTORY_SEPARATOR;
        $path = Path::realpath($this->folders[$namespace] . $ds . $file . '.php');

        if ($this->pathUtil->insideRoot($path)) {
            if (file_exists($path)) {
                return $path;
            }

            throw new ValueError("Template '$path' does not exists");
        }

        throw new ValueError("Template '$path' is outside of the project root directory");
    }

    protected static function load(string $template, array $context = []): void
    {
        // Hide $template. Could be overwritten if $context['template'] exists.
        $____template____ = $template;

        extract($context);

        /** @psalm-suppress UnresolvableInclude */
        include $____template____;
    }

    public function exists(string $template): bool
    {
        try {
            $path = $this->getPath($template);

            if (empty($path)) {
                return false;
            }

            return true;
        } catch (ValueError) {
            return false;
        }
    }
}
