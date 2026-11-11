<?php

declare(strict_types=1);

/*
 * For an application that does not use Composer: require this file once, and the classes of
 * the SDK (Naxa\Sdk\...) load by themselves.
 */

if (PHP_VERSION_ID < 80300) {
    throw new RuntimeException('The Naxa SDK requires PHP 8.3 or newer.');
}
foreach (['sodium', 'curl', 'json'] as $extension) {
    if (!extension_loaded($extension)) {
        throw new RuntimeException('The Naxa SDK requires the PHP extension "' . $extension . '".');
    }
}

spl_autoload_register(static function (string $class): void {
    if (!str_starts_with($class, 'Naxa\\Sdk\\')) {
        return;
    }
    $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 9)) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
