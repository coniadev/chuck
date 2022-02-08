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
    $route = (new Route('index', '/', function (Request $request) {}))->method('GET');
    $router->add($route);
    $app = new App(new Request($router, $config));
    $app->run();
```
