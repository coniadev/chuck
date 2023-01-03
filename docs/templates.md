Templates
=========

Require a template engine with a renderer. E. g.:

    composer require conia/boiler

Use it:

    use Conia\Chuck\{App, Config, Router, Route, Request, ResponseFactory};
    use Conia\Boiler\Renderer;

    $config = new Config('chuck');

    // Add template support
    $config->addRenderer('template', Renderer::class, '/path/to/templates');
