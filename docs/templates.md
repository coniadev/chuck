Templates
=========

Require the template engine

    composer require conia/boiler

Use it:


    use Conia\Chuck\{App, Config, Router, Route, Request, ResponseFactory};
    use Conia\Chuck\Renderer\TemplateRenderer;

    $config = new Config('chuck');

    // Add template support
    $config->addRenderer('template', TemplateRenderer::class, '/path/to/templates');
    use Conia\Chuck\Renderer\TemplateRenderer;
