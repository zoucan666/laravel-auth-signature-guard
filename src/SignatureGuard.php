<?php
/**
 * @copyright Copyright (c) 2018 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larvacent.com/
 * @license http://www.larvacent.com/license/
 */

namespace Larva\Auth;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Laravel\Passport\ClientRepository;

/**
 * Class SignatureGuard
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class SignatureGuard
{
    /**
     * The user provider implementation.
     *
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected $provider;

    /**
     * The client repository instance.
     *
     * @var \Laravel\Passport\ClientRepository
     */
    protected $clients;

    /**
     * Create a new authentication guard.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider $provider
     * @param ClientRepository $clients
     */
    public function __construct(UserProvider $provider, ClientRepository $clients)
    {
        $this->provider = $provider;
        $this->clients = $clients;
    }

    /**
     * 获取传入请求的用户。
     *
     * @param  \Illuminate\Http\Request $request
     * @return mixed
     */
    public function user(Request $request)
    {
        //获取参数
        $params = $request->except(['signature']);
        //检查必要的参数
        if (!isset($params['app_id']) || !isset($params['timestamp'])) {
            return null;
        }

        if (($client = $this->clients->findActive($params['app_id'])) != null) {
            return null;
        }
        //排序参数
        ksort($params);
        $stringToSign = urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));


        $signature = base64_encode(hash_hmac('sha1', $stringToSign, $client->secret, true));
        if ($request->input(['signature']) == $signature) {
            return $client->user;
        }
        return null;
    }
}