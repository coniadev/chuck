Chuck framework
===============


Default:

```php
    use Chuck\{App, Route};
    $app = App::create(__DIR__ . '/config.php');
    $app->route(Route::get('index', '/', function (Request $request) {}));
    $app->run();
```


Delarative:

```php
    use Chuck\{App, Config, Router, Route, Request};

    $config = new Config(__DIR__ . '/config.php');
    $router = new Router();
    $router->add(new Route('index', '/', function (Request $request) {}));
    $app = new App(new Request($config, $router));
    $app->run();
```
