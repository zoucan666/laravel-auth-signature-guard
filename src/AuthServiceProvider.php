<?php
/**
 * @copyright Copyright (c) 2018 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larvacent.com/
 * @license http://www.larvacent.com/license/
 */

namespace Larva\Auth;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\ClientRepository;

/**
 * Class AuthServiceProvider
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class AuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        Auth::extend('signature', function ($app, $name, array $config) {
            return new RequestGuard(function ($request) use ($config) {
                return (new SignatureGuard(
                    Auth::createUserProvider($config['provider']),
                    $this->app->make(ClientRepository::class)
                ))->user($request);
            }, $this->app['request']);
        });
    }
}