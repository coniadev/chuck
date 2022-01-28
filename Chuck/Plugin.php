<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\App;
use Chuck\RequestInterface;
use Chuck\ResponseInterface;

abstract class Plugin
{
    public function __construct(public ?RequestInterface $request)
    {
    }

    /**
     * Return an array with the following structure
     *
     * [
     *     'slug' => 'A unique identifier also used as url slug',
     *     'title' => 'The public title',
     *     'summary' => 'A short description of what the plugin does.
     *                   Is visible in the admin interface',
     *     'version' => '1.0.0',
     *     'admin' => [
     *        'scripts' => [], // optional list of js files
     *        'styles' => [], // optional list of js files
     *      ],
     *     'frontend' => [
     *        'scripts' => [], // optional list of js files
     *        'styles' => [], // optional list of js files
     *      ],
     *      'sql' => 'path/to/sql/files' // optional,
     *      'templates' => '<plugin>:path/to/templates' // optional,
     *      'migrations' => 'path/to/migrations' // optional,
     * ]
     */
    abstract public function info(): array;

    public function getInfo(): array
    {
        $info = $this->info();
        $info['class'] = get_class($this);

        return $info;
    }

    public function getContent(): array
    {
        return [];
    }

    public function addRoutes(App $app): void
    {
        return;
    }

    protected function getAssets(
        string $section,
        string $key,
    ): \Generator {
        $scripts = $this->info[$section][$key] ?? [];
        $devel = $this->request->devel();
        $devPort = $devel ? (string)$this->request->config->get('devport') : null;
        $pluginSlugSegment = $this->info()['slug'];

        foreach ($scripts as $script) {
            if (str_starts_with($script, 'http')) {
                yield $script;
            } else {
                if ($devel) {
                    yield "http://localhost:$devPort/plugin/$pluginSlugSegment/$script";
                } else {
                    yield $this->request->routeUrl(
                        'plugin:asset',
                        [
                            'plugin' => $pluginSlugSegment, // the plugin identifying part of the slug
                            'slug' => $script, // the file path part of the slug
                        ]
                    );
                }
            }
        }
    }

    public function getScripts(): \Generator
    {
        return $this->getAssets('frontend', 'scripts');
    }

    public function getStyles(): \Generator
    {
        return $this->getAssets('frontend', 'styles');
    }

    public function getAdminScripts(): \Generator
    {
        return $this->getAssets('admin', 'scripts');
    }

    public function getAdminStyles(): \Generator
    {
        return $this->getAssets('admin', 'styles');
    }

    public function getAssetPath(string $slug): string
    {
        $ref = new \ReflectionClass($this::class);
        $dir = dirname($ref->getFileName());

        $path = realpath($dir . DIRECTORY_SEPARATOR . $slug);

        if (!$path) {
            throw new \ErrorException(
                'Plugin asset not found. Plugin: ' .
                    $this->info()['title']
            );
        }

        return $path;
    }

    public static function get(?RequestInterface $request, string $class): Plugin
    {
        if (class_exists($class)) {
            return new $class($request);
        } else {
            throw new \Exception('Plugin class does not exist');
        }
    }

    public static function all(ConfigInterface $config, ?RequestInterface $request): array
    {
        static $plugins = null;

        if ($plugins === null) {
            $plugins = [];

            foreach ($config->get('plugins') as $plugin) {
                $plugins[] = self::get($request, $plugin['class']);
            }
        }

        return $plugins;
    }


    public static function gui(ConfigInterface $config, ?RequestInterface $request): array
    {
        static $plugins = null;

        if ($plugins === null) {
            $plugins = [];

            foreach ($config->get('plugins') as $plugin) {
                $plugin = $plugin['gui'] ?? false;

                if ($plugin) {
                    $plugins[] = $plugin;
                }
            }
        }

        return $plugins;
    }

    protected static function dirs(array $plugins, string $key): array
    {
        $dirs = [];

        foreach ($plugins as $plugin) {
            $dir = $plugin->info()[$key] ?? null;

            if ($dir) {
                $dirs[] = $dir;
            }
        }

        return $dirs;
    }

    public static function sqlDirs(ConfigInterface $config, RequestInterface $request): array
    {
        return self::dirs(self::all($config, $request), 'sql');
    }

    public static function templateDirs(ConfigInterface $config, RequestInterface $request): array
    {
        return self::dirs(self::all($config, $request), 'templates');
    }

    public static function migrationDirs(ConfigInterface $config): array
    {
        return self::dirs(self::all($config, null), 'migrations');
    }
}
