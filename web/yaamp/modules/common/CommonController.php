<?php
class CommonController extends CController
{
    public $memcache;
    public $t1;

    // read-only via getAdmin()
    private $admin = false;
    protected function getAdmin()
    {
        return $this->admin;
    }

    protected function elapsedTime()
    {
        $t2 = microtime(true);
        return ($t2 - $this->t1);
    }

    // True when the browser says the request was started by another web site
    // (a link, form, image or script on a foreign page), i.e. a possible CSRF.
    // Modern browsers send Sec-Fetch-Site, older ones Origin and/or Referer.
    // Requests without any of these headers (curl, scripts) are not cross-site.
    public function isCrossSiteRequest()
    {
        $site = arraySafeVal($_SERVER, 'HTTP_SEC_FETCH_SITE', '');
        if ($site == 'cross-site') return true;
        if ($site == 'same-origin' || $site == 'none') return false;

        $host = strtolower(arraySafeVal($_SERVER, 'HTTP_HOST', ''));
        foreach (array('HTTP_ORIGIN', 'HTTP_REFERER') as $header) {
            $value = arraySafeVal($_SERVER, $header, '');
            if (empty($value)) continue;
            if ($value == 'null') return true; // sandboxed/opaque origin
            $url = parse_url($value);
            if (!is_array($url) || empty($url['host'])) return true;
            $from = strtolower($url['host']) . (isset($url['port']) ? ':' . $url['port'] : '');
            return ($from != $host);
        }
        return false;
    }

    protected function sendSecurityHeaders()
    {
        if (php_sapi_name() == 'cli' || headers_sent()) return;
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }

    protected function beforeAction($action)
    {
        //	debuglog("before action ".$action->getId());
        $this->memcache = new YaampMemcache;
        $this->t1 = microtime(true);

        $this->sendSecurityHeaders();

        // CSRF: refuse forms posted from foreign sites (the API is used by scripts)
        if (php_sapi_name() != 'cli' && $this->id != 'api' && app()->request->isPostRequest && $this->isCrossSiteRequest())
        {
            debuglog("cross-site POST refused {$this->id}/{$action->id} from ".arraySafeVal($_SERVER, 'REMOTE_ADDR'));
            throw new CHttpException(403, 'Cross-site request refused.');
        }

        if (user()
            ->getState('yaamp_admin'))
        {
            $this->admin = true;
            $client_ip = arraySafeVal($_SERVER, 'REMOTE_ADDR');
            if (!isAdminIP($client_ip))
            {
                user()->setState('yaamp_admin', false);
                debuglog("admin attempt from $client_ip");
                $this->admin = false;
            }
            // CSRF: admin actions are plain links, never grant them to a
            // request initiated by another site (the session is kept).
            else if ($this->isCrossSiteRequest())
            {
                debuglog("admin rights ignored for cross-site request {$this->id}/{$action->id} from $client_ip");
                $this->admin = false;
            }
        }

        $algo = user()->getState('yaamp-algo');
        if (!$algo) user()->setState('yaamp-algo', YAAMP_DEFAULT_ALGO);

        return true;
    }

    protected function afterAction($action)
    {
        //	debuglog("after action ".$action->getId());
        $d1 = $this->elapsedTime();

        $url = "$this->id/{$this
            ->action->id}";
        $this
            ->memcache
            ->add_monitoring_function($url, $d1);
    }

    public function actionMaintenance()
    {
        $this->render('maintenance');
    }

    public function goback($count = - 1)
    {
        Javascript("window.history.go($count);");
        die;
    }

}
