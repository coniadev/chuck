<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Log;

uses(TestCase::class);


test('Log to file', function () {
    // capture output of error_log calls in a temporary file
    // to prevent it printed to the console.
    $default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];

    $logger = new Log($this->request(options: ['path.logfile' => $logfile]));

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->alert("Kelly");

    $output = file_get_contents($logfile);

    expect($output)->toContain('] DEBUG: Scott');
    expect($output)->toContain('] INFO: Steve');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] ALERT: Kelly');

    ini_set('error_log', $default);
});

test('Log to php sapi', function () {
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];
    $default = ini_set('error_log', $logfile);

    $logger = new Log($this->request());

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->alert("Kelly");

    $output = file_get_contents($logfile);

    expect($output)->toContain('] DEBUG: Scott');
    expect($output)->toContain('] INFO: Steve');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] ALERT: Kelly');

    ini_set('error_log', $default);
});


test('Log with higher debug level', function () {
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];
    $default = ini_set('error_log', $logfile);

    $logger = new Log($this->request(options: ['loglevel' => Log::WARNING]));

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->alert("Kelly");

    $output = file_get_contents($logfile);

    expect($output)->not->toContain('] DEBUG: Scott');
    expect($output)->not->toContain('] INFO: Steve');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] ALERT: Kelly');

    ini_set('error_log', $default);
});
