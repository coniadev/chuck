<?php

declare(strict_types=1);

namespace Chuck;

use \PHPMailer\PHPMailer\PHPMailer;

class Config implements ConfigInterface
{
    protected array $config;

    public function __construct(string $configFile, array $custom = [])
    {
        $defaults = require 'defaults.php';
        $appConfig = require $configFile;

        $this->config = array_replace_recursive(
            $defaults,
            $this->getPathDefaults($configFile),
            $appConfig,
            $custom
        );
    }

    protected function getPathDefaults(string $configFile): array
    {
        $ds = DIRECTORY_SEPARATOR;
        $appDir = dirname($configFile);
        $rootDir = dirname($appDir);

        return [
            'path' => [
                'app' => $appDir,
                'root' => $rootDir,
                'migrations' => $rootDir . $ds . 'db' . $ds . 'migrations',
                'sql' => [$appDir . $ds . 'Model' . $ds . 'sql'],
                'templates' => $appDir . $ds . 'Templates',
            ]
        ];
    }

    public function get(string $key)
    {
        return $this->config[$key];
    }

    public function getOr(string $key, $default)
    {
        return $this->config[$key] ?? $default;
    }

    public function path(string $key): string|array
    {
        $path = $this->config['path'][$key];

        if (is_array($path)) {
            return array_map(function ($p) {
                return Util::realpath($p);
            }, $path);
        }

        return Util::realpath($this->config['path'][$key]);
    }

    public function di(string $key): string
    {
        return $this->config['di'][$key];
    }

    public function renderer(string $key): string
    {
        return $this->config['renderer'][$key];
    }

    public function getMailer(): PHPMailer
    {
        $config = $this->get('mail');
        $mailer = new PHPMailer(true);  // raise exception on error
        $mailer->Host = $config['host'];
        $mailer->Port = $config['port'];
        $mailer->Username = $config['username'];
        $mailer->Password = $config['password'];
        $mailer->CharSet = 'UTF-8';
        $mailer->isSMTP();
        $mailer->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        $mailer->SMTPAuth = true;
        $mailer->setFrom($config['default_sender'], $config['default_sender']);

        return $mailer;
    }
}
