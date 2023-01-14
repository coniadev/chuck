<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Setup;

use Conia\Chuck\App;
use Conia\Chuck\Config;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Http\Factory;
use Conia\Chuck\Http\Nyholm;
use Conia\Chuck\Logger;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Renderer\JsonRenderer;
use Conia\Chuck\Renderer\Renderer;
use Conia\Chuck\Renderer\TextRenderer;
use Conia\Chuck\Request;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

/**
 * @internal
 *
 * @coversNothing
 */
class TestCase extends BaseTestCase
{
    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $_SERVER['HTTP_HOST'] = 'www.example.com';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    protected function tearDown(): void
    {
        unset(
            $_SERVER['HTTP_HOST'],
            $_SERVER['REQUEST_METHOD'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['SERVER_PROTOCOL'],
            $_SERVER['CONTENT_TYPE'],
            $_SERVER['QUERY_STRING'],
            $_SERVER['argv'],
            $_SERVER['HTTPS'],
            $_SERVER['HTTP_X_FORWARDED_PROTO'],
            $_SERVER['REQUEST_SCHEME']
        );

        global $_GET;
        $_GET = [];
        global $_POST;
        $_POST = [];
        global $_FILES;
        $_FILES = [];
        global $_COOKIE;
        $_COOKIE = [];
    }

    public function set(string $method, array $values): void
    {
        global $_GET;
        global $_POST;
        global $_COOKIE;

        foreach ($values as $key => $value) {
            if (strtoupper($method) === 'GET') {
                $_GET[$key] = $value;

                continue;
            }
            if (strtoupper($method) === 'POST') {
                $_POST[$key] = $value;

                continue;
            }
            if (strtoupper($method) === 'COOKIE') {
                $_COOKIE[$key] = $value;
            } else {
                throw new ValueError("Invalid method '{$method}'");
            }
        }
    }

    public function setMethod(string $method): void
    {
        $_SERVER['REQUEST_METHOD'] = strtoupper($method);
    }

    public function setContentType(string $contentType): void
    {
        $_SERVER['HTTP_CONTENT_TYPE'] = $contentType;
    }

    public function setRequestUri(string $url): void
    {
        if (substr($url, 0, 1) === '/') {
            $_SERVER['REQUEST_URI'] = $url;
        } else {
            $_SERVER['REQUEST_URI'] = "/{$url}";
        }
    }

    public function setHost(string $host): void
    {
        $_SERVER['HTTP_HOST'] = $host;
    }

    public function setQueryString(string $qs): void
    {
        $_SERVER['QUERY_STRING'] = $qs;
    }

    public function enableHttps(?string $serverKey = null): void
    {
        if ($serverKey) {
            $_SERVER[$serverKey] = 'https';
        } else {
            $_SERVER['HTTPS'] = 'on';
        }
    }

    public function disableHttps(): void
    {
        unset($_SERVER['HTTPS'], $_SERVER['REQUEST_SCHEME'], $_SERVER['HTTP_X_FORWARDED_PROTO']);
    }

    public function config(bool $debug = false): Config
    {
        return new Config('chuck', debug: $debug);
    }

    public function app(Config $config = null): App
    {
        return App::create($config ?? $this->config());
    }

    public function registry(
        ?Request $request = null,
        ?Config $config = null,
        bool $autowire = true,
    ): Registry {
        $registry = new Registry(autowire: $autowire);
        $request = $request ?: $this->request();
        $config = $config ?: $this->config();

        $registry->add(Registry::class, $registry);
        $registry->add(Request::class, $request);
        $registry->add(Factory::class, Nyholm::class);
        $registry->add($request::class, $request);
        $registry->add(Config::class, $config);
        $registry->add($config::class, $config);
        $registry->add(LoggerInterface::class, function (): LoggerInterface {
            return new Logger();
        });

        $registry->tag(Renderer::class)->add('text', TextRenderer::class)->asIs();
        $registry->tag(Renderer::class)->add('json', JsonRenderer::class)->asIs();

        return $registry;
    }

    public function factory(): Factory
    {
        return $this->registry()->get(Factory::class);
    }

    public function psr7Request(): ServerRequestInterface
    {
        $psr17Factory = new Psr17Factory();

        $creator = new \Nyholm\Psr7Server\ServerRequestCreator(
            $psr17Factory, // ServerRequestFactory
            $psr17Factory, // UriFactory
            $psr17Factory, // UploadedFileFactory
            $psr17Factory  // StreamFactory
        );

        return $creator->fromGlobals();
    }

    public function psr7Response(): ResponseInterface
    {
        $psr17Factory = new Psr17Factory();

        return $psr17Factory->createResponse();
    }

    public function request(
        ?string $method = null,
        ?string $url = null,
        ?bool $https = null,
    ): Request {
        if ($method) {
            $this->setMethod($method);
        }

        if ($url) {
            $this->setRequestUri($url);
        }

        if (is_bool($https)) {
            if ($https) {
                $this->enableHttps();
            } else {
                $this->disableHttps();
            }
        }

        return new Request($this->psr7Request());
    }

    public function setupFile()
    {
        global $_FILES;

        $_FILES = [
            'myfile' => [
                'error' => UPLOAD_ERR_OK,
                'name' => '../malic/chuck-test-file.php',
                'size' => 123,
                'tmp_name' => __FILE__,
                'type' => 'text/plain',
            ],
            'failingfile' => [
                'error' => UPLOAD_ERR_PARTIAL,
                'name' => 'chuck-failing-test-file.php',
                'size' => 123,
                'tmp_name' => '',
                'type' => 'text/plain',
            ],
            'nested' => [
                'myfile' => [
                    'error' => UPLOAD_ERR_OK,
                    'name' => '../malic/chuck-test-file.php',
                    'size' => 123,
                    'tmp_name' => __FILE__,
                    'type' => 'text/plain',
                ],
            ],
        ];
    }

    public function setupFiles()
    {
        global $_FILES;

        $_FILES = [
            'myfile' => [
                'error' => [UPLOAD_ERR_OK, UPLOAD_ERR_PARTIAL],
                'name' => ['test.php', 'test2.php'],
                'size' => [123, 234],
                'tmp_name' => [__FILE__, __FILE__],
                'type' => ['text/plain', 'text/plain'],
            ],
            'nested' => [
                'myfile' => [
                    'error' => [UPLOAD_ERR_OK, UPLOAD_ERR_PARTIAL],
                    'name' => ['test.php', 'test2.php'],
                    'size' => [123, 234],
                    'tmp_name' => [__FILE__, __FILE__],
                    'type' => ['text/plain', 'text/plain'],
                ],
            ],
        ];
    }

    public function fullTrim(string $text): string
    {
        return trim(
            preg_replace(
                '/> </',
                '><',
                preg_replace(
                    '/\s+/',
                    ' ',
                    preg_replace('/\n/', '', $text)
                )
            )
        );
    }
}
