<?php
/**
 * @copyright Copyright (c) 2018 Jinan Larva Information Technology Co., Ltd.
 * @link http://www.larvacent.com/
 * @license http://www.larvacent.com/license/
 */

namespace Larva\Auth;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\Request;
use Laravel\Passport\ClientRepository;

/**
 * Class SignatureGuard
 *
 * @author Tongle Xu <xutongle@gmail.com>
 */
class SignatureGuard
{
    const SIGNATURE_METHOD_HMACSHA1 = 'HMAC-SHA1';
    const SIGNATURE_METHOD_HMACSHA256 = 'HMAC-SHA256';

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
     * @throws AuthenticationException
     */
    public function user(Request $request)
    {
        //验证公共请求参数
        if (!$request->has('app_id')) {
            throw new AuthenticationException('Missing app_id parameter.');
        }

        if (!$request->has('timestamp')) {
            throw new AuthenticationException('Missing timestamp parameter.');
        }

        if (!$request->has('signature')) {
            throw new AuthenticationException('Missing signature parameter.');
        }

        if (!$request->has('signature_method')) {
            throw new AuthenticationException('Missing signature_method parameter.');
        }

        if (!$request->has('signature_version')) {
            throw new AuthenticationException('Missing signature_version parameter.');
        }

        if (!$request->has('signature_nonce')) {
            throw new AuthenticationException('Missing signature_nonce parameter.');
        }

        //获取参数
        $params = $request->except(['signature']);

        //检查时间戳，误差1分钟
        if ((time() - intval($params['timestamp'])) > 60) {
            throw new AuthenticationException('Client time is incorrect.');
        }

        //获取有效的 Client
        if (($client = $this->clients->findActive($params['app_id'])) == null) {
            throw new AuthenticationException('App_id is incorrect.');
        }

        if ($request->input('signature') != $this->getSignature($params, $client->secret)) {
            throw new AuthenticationException('Signature verification failed');
        }
        return $client->user;
    }

    /**
     * Calculate signature for request
     *
     * @param array $params parameters.
     * @param $key
     * @return string
     * @throws AuthenticationException
     */
    protected function getSignature(array $params, $key)
    {
        //参数排序
        ksort($params);
        $stringToSign = urlencode(http_build_query($params, null, '&', PHP_QUERY_RFC3986));

        //签名
        if ($params['signature_method'] == self::SIGNATURE_METHOD_HMACSHA256) {
            return base64_encode(hash_hmac('sha256', $stringToSign, $key, true));
        } elseif ($params['signature_method'] == self::SIGNATURE_METHOD_HMACSHA1) {
            return base64_encode(hash_hmac('sha1', $stringToSign, $key, true));
        }
        throw new AuthenticationException('This signature method is not supported.');
    }
}