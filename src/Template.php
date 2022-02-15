<?php

declare(strict_types=1);

namespace Chuck;

use \ValueError;
use Chuck\Util\Path;


class Template implements TemplateInterface
{
    protected RequestInterface $request;
    protected array $folders = [];
    protected array $defaults;
    protected string $path;

    public function __construct(
        RequestInterface $request,
        array $defaults = [],
    ) {
        $this->request = $request;
        $config = $request->config;

        $this->defaults = array_merge([
            'config' => $config,
            'request' => $request,
            'router' => $request->router,
            'devel' => $config->get('devel'),
        ], $defaults);

        $this->pathUtil = new Path($config);
        $this->addFolders($config->get('templates'));
    }

    protected function addFolders(array $folders): void
    {
        foreach ($folders as $key => $dir) {
            if (is_int($key)) {
                throw new ValueError("Template paths must be key/value pairs");
            }

            if (!$this->pathUtil->insideRoot($dir)) {
                throw new ValueError("Template paths is not inside the project root directory: $dir");
            }

            if (!is_dir($dir)) {
                throw new ValueError("Template directory does not exists: $dir");
            }

            $this->folders[$key] = $dir;
        }
    }

    public function render(string $template, $context = []): string
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

            print("$namespace $file\n");

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

    protected static function load(string $template, array $context = [])
    {
        // Hide $template. Could be overwritten if $context['template'] exists.
        $____template____ = $template;

        extract($context);

        return include $____template____;
    }
}
