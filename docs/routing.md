# Routing

```php
    // Single route
    $route = Route::get(/', function (Request $request) {
        return [1, 2, 3];
    })->render('json');
    $app->addRoute($route);

    $route = (new Route('/', function (Request $request) {}))->method('GET','POST');


    // Route groups
    $app->group(new Group('admin:', '/admin/', function (Group $group) {
        $group->addRoute(Route::get(...);
        $group->addRoute(Route::post(...);

        // helpers 
        $group->get('/api/users', () => []);
        $group->post('/api/users', () => []);
    });
```

