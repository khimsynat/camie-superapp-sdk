<?php

namespace CamIE\SuperApp\Laravel\Facades;

use Illuminate\Support\Facades\Facade;
use CamIE\SuperApp\CamIESuperAppSDK;

class SuperApp extends Facade
{
    protected static function getFacadeAccessor()
    {
        return CamIESuperAppSDK::class;
    }
}