<?php

declare(strict_types=1);

class Superuser extends Chuck\Cli\Command
{
    public static string $group = 'General';
    public static string $title = 'Add superuser';

    public function run(Chuck\ConfigInterface $config, string ...$args): void
    {
        $class = $config->di('Router');
        $router = new $class();
        $class = $config->di('Request');
        $request = new $class($config, $router);
        $model = $config->di('Model');
        $model::init($request);
        $auth = $config->di('Auth');

        $params = [];

        echo "Create a superuser\n\n";
        $params['email'] = readline('Email: ');
        $params['full_name'] = readline('Full Name: ');
        $params['display_name'] = readline('Display Name: ');
        $params['pwhash'] = password_hash(
            readline('Password: '),
            PASSWORD_ARGON2ID
        );

        $result = $auth::addSuperuser($params);
        if ($result['success']) {
            echo "\nSuccessfully created superuser: " . $params['email'] . "\n";
        } else {
            echo "\nError occured. Please review your data!\n";
            echo $result['message'] . "\n";
        }
    }
}

return new Superuser();
