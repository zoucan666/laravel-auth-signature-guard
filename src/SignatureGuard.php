<?php
/**
 * @copyright Copyright (c) 2018 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larvacent.com/
 * @license http://www.larvacent.com/license/
 */

namespace Larva\Auth;

use Illuminate\Foundation\Auth\User;
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
     * @return User|void
     */
    public function user(Request $request)
    {
        if (!$request->has(['app_id', 'timestamp'])) {
            return;
        }
        //获取参数
        $params = $request->except(['signature']);

        //获取有效的Client
        if (($client = $this->clients->findActive($params['app_id'])) == null) {
            return;
        }
        //检查时间戳，误差1分钟
        if ((time() - intval($params['timestamp'])) > 3600*24) {
            return;
        }

        //排序参数
        //按照键名对关联数组进行升序排序
        ksort($params);

        //编码
        $stringToSign = urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));

        //签名
        $signature = base64_encode(hash_hmac('sha1', $stringToSign, $client->secret, true));

        if ($request->input('signature') == $signature) {
            return $client->user;
        }
        return;
    }
}