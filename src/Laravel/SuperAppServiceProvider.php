<?php

namespace CamIE\SuperApp\Laravel;

use Illuminate\Support\ServiceProvider;
use CamIE\SuperApp\CamIESuperAppSDK;

class SuperAppServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/superapp.php', 'superapp');

        $this->app->singleton(CamIESuperAppSDK::class, function ($app) {
            return new CamIESuperAppSDK(config('superapp.domain'));
        });
    }

    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../../config/superapp.php' => config_path('superapp.php'),
            ], 'superapp-config');
        }
    }
}