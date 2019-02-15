<?php
/**
 * @copyright Copyright (c) 2018 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larvacent.com/
 * @license http://www.larvacent.com/license/
 */

namespace Larva\Auth;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Laravel\Passport\ClientRepository;
use Psr\Http\Message\RequestInterface;

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
        if (!$request->has(['app_id', 'timestamp', 'signature_method', 'signature_nonce'])) {
            return;
        }

        //获取参数
        $params = $request->except(['signature']);

        //获取有效的Client
        if (($client = $this->clients->findActive($params['app_id'])) == null) {
            return;
        }
        //检查时间戳，误差1分钟
        if ((time() - intval($params['timestamp'])) > 3600 * 24) {
            return;
        }
        if ($request->input('signature') == $this->getSignature($request, $params, $client->secret)) {
            return $client->user;
        }
        return;
    }


    /**
     * Calculate signature for request
     *
     * @param Request $request Request to generate a signature for
     * @param array $params parameters.
     *
     * @return string
     *
     * @throws \RuntimeException
     */
    protected function getSignature(Request $request, array $params, $secret)
    {
        //参数排序
        ksort($params);
        $stringToSign = urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));
        return base64_encode(hash_hmac('sha1', $stringToSign, $secret, true));
    }
}