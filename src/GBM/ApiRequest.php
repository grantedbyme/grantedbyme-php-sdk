<?php
/**
 * API helper
 *
 * PHP version 5
 *
 * @category SDK
 * @package  GBM
 * @author   GrantedByMe <info@grantedby.me>
 * @access   private
 * @license  https://grantedby.me/licenses/php/license.md MIT
 * @version  Release: <release_id>
 * @link     https://grantedby.me
 */
namespace GBM {

    /**
     * API helper
     *
     * @category SDK
     * @package  GBM
     * @author   GrantedByMe <info@grantedby.me>
     * @access   private
     * @license  https://raw.githubusercontent.com/grantedbyme/grantedbyme-php-sdk/master/LICENSE MIT
     * @version  Release: <release_id>
     * @link     https://grantedby.me
     */
    class ApiRequest
    {
        ////////////////////////////////////////
        // Public Static Variables
        ////////////////////////////////////////

        // Waiting for user response
        public static $STATUS_PENDING = 1;
        // User confirmed
        public static $STATUS_LINKED = 2;
        // User validated
        public static $STATUS_VALIDATED = 3;
        // Timeout
        public static $STATUS_EXPIRED = 4;
        // Ban
        public static $STATUS_BANNED = 5;

        // Single Factor Auth. Mode, PWD Needed
        public static $MODE_SFA_PWD = 1;
        // Single Factor Auth. Mode, GBM Needed
        public static $MODE_SFA_GBM = 2;
        // Two Factor Auth. Mode, One Needed
        public static $MODE_2FA_OPT = 3;
        // Two Factor Auth. Mode, Both Needed
        public static $MODE_2FA_STRICT = 4;

        // TBD
        public static $TOKEN_ACCOUNT = 1;
        // TBD
        public static $TOKEN_SESSION = 2;
        // TBD
        public static $TOKEN_AUTHORIZE = 3;
        // TBD
        public static $TOKEN_ACTIVATE = 4;
        // TBD
        public static $TOKEN_DEACTIVATE = 5;

        ////////////////////////////////////////
        // Private Variables
        ////////////////////////////////////////

        /**
         * TBD
         *
         * @var string
         * @access private
         */
        private $service_key;

        /**
         * TBD
         *
         * @var array
         * @access private
         */
        private $config;

        /**
         * TBD
         *
         * @var mixed
         * @access private
         */
        private $crypto;

        ////////////////////////////////////////
        // Constructor
        ////////////////////////////////////////

        /**
         * Constructor
         *
         * @param array $config The configuration array
         *
         * @throws ApiCryptoException
         */
        public function __construct($config)
        {
            // check for OpenSSL extension_loaded
            if (!extension_loaded('openssl')) {
                throw new ApiCryptoException('Missing OpenSSL extension, please enable it in php.ini');
            }
            // initialize configuration
            $this->setConfig($config);
            $this->crypto = new ApiCrypto($this->config);
        }

        ////////////////////////////////////////
        // Public Methods
        ////////////////////////////////////////

        /**
         * Sets configuration options
         *
         * @param array $config The configuration array
         */
        public function setConfig($config)
        {
            if (!isset($config)) {
                return;
            }
            if (!isset($this->config)) {
                $this->config = $config;
            } else {
                $this->config = array_merge($this->config, $config);
            }
        }

        /**
         * Returns the API URL
         *
         * @return string
         */
        public function getApiUrl()
        {
            if (isset($this->config) && isset($this->config['api_url']) && self::isValidString($this->config['api_url'])) {
                return $this->config['api_url'];
            }
            return ApiSettings::$HOST;
        }

        /**
         * Returns the Crypto wrapper
         *
         * @return ApiCrypto
         */
        public function getCrypto()
        {
            return $this->crypto;
        }

        /**
         * Returns whether the SDK is activated using a RSA key pair
         *
         * @return bool
         */
        public function isActivated()
        {
            return $this->crypto->isLoaded();
        }

        /**
         * Get activation public key
         *
         * @return array
         * @throws ApiRequestException
         */
        private function activateHandshake($public_key)
        {
            if (!self::isValidString($public_key)) {
                throw new ApiRequestException('invalid parameters in activateHandshake()');
            }
            $params = array();
            $params['public_key'] = $public_key;
            $params['timestamp'] = time();
            // post unencrypted
            $url = $this->getApiUrl() . 'activate_handshake' . '/';
            $result = CurlRequest::post($url, json_encode($params));
            // decode json result
            $response = json_decode($result, true);
            // check for valid response
            if (isset($response['success']) && $response['success'] == true && isset($response['public_key'])) {
                $this->crypto->setPublicKey($response['public_key']);
            }
            //print_r($response);
            // return result
            return $response;
        }

        /**
         * Activate a service
         *
         * @param string $service_key TBD
         * @param string $grantor TBD
         *
         * @return array
         * @throws ApiRequestException
         */
        public function activateService($service_key, $grantor)
        {
            if (!self::isValidString($service_key) || !self::isValidString($grantor)) {
                throw new ApiRequestException('invalid parameters in activateService()');
            }
            // sanitize
            $service_key = htmlspecialchars(trim($service_key));
            $grantor = htmlspecialchars(trim($grantor));
            // set service key for default headers
            $this->service_key = $service_key;
            // generate RSA key pair
            $keypair = $this->crypto->generateKeyPair();
            $handshake = $this->activateHandshake($keypair['public_key']);
            // set default headers
            $params = $this->getDefaultParams();
            $params['service_key'] = $service_key;
            $params['grantor'] = $grantor;
            // do api call
            $response = $this->apiCall($params, 'activate_service');
            // check for valid response
            if (isset($response['success'])) {
                if ($response['success'] == true) {
                    $response['server_key'] = $handshake['public_key'];
                    $response = array_merge($response, $params, $keypair);
                }
            } else {
                $this->service_key = false;
            }
            //print_r($response);
            // return result
            return $response;
        }

        /**
         * Deactivate a service
         *
         * @return array
         * @throws ApiRequestException
         */
        public function deactivateService()
        {
            $params = $this->getDefaultParams();
            return $this->apiCall($params, 'deactivate_service');
        }

        /**
         * Links Users Service account with a GBM User account
         *
         * @param string $token TBD
         * @param string $grantor TBD
         *
         * @return array
         * @throws ApiRequestException
         */
        public function linkAccount($token, $grantor)
        {
            if (!self::isValidString($token) || !self::isValidString($grantor)) {
                throw new ApiRequestException('invalid parameters in linkAccount()');
            }
            $params = $this->getDefaultParams();
            $params['token'] = htmlspecialchars(trim($token));
            $params['grantor'] = htmlspecialchars(trim($grantor));
            return $this->apiCall($params, 'link_account');
        }

        /**
         * Unlinks Users Service account with a GBM User account
         *
         * @param string $grantor TBD
         *
         * @return array
         * @throws ApiRequestException
         */
        public function unlinkAccount($grantor)
        {
            if (!self::isValidString($grantor)) {
                throw new ApiRequestException('invalid parameters in unlinkAccount()');
            }
            $params = $this->getDefaultParams();
            $params['grantor'] = hash('sha512', htmlspecialchars(trim($grantor)));
            return $this->apiCall($params, 'unlink_account');
        }

        /**
         * Returns an account migration token
         *
         * @return array
         * @throws ApiRequestException
         */
        public function getAccountToken()
        {
            return $this->getToken(\GBM\ApiRequest::$TOKEN_ACCOUNT);
        }

        /**
         * Returns an account authentication token
         *
         * @return array
         * @throws ApiRequestException
         */
        public function getSessionToken()
        {
            return $this->getToken(\GBM\ApiRequest::$TOKEN_SESSION);
        }

        /**
         * Returns an account registration token
         *
         * @return array
         * @throws ApiRequestException
         */
        public function getRegisterToken()
        {
            return $this->getToken(\GBM\ApiRequest::$TOKEN_ACTIVATE);
        }

        /**
         * Returns a new token by type
         *
         * @return array
         * @throws ApiRequestException
         */
        public function getToken($token_type)
        {
            $params = $this->getDefaultParams();
            $params['token_type'] = $token_type;
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $params['http_user_agent'] = $_SERVER['HTTP_USER_AGENT'];
            }
            if (isset($_SERVER['REMOTE_ADDR'])) {
                $params['remote_addr'] = $_SERVER['REMOTE_ADDR'];
            }
            return $this->apiCall($params, 'get_session_token');
        }

        /**
         * Return session state
         *
         * @param string $token TBD
         *
         * @return array
         * @throws ApiRequestException
         */
        public function getSessionState($token)
        {
            if (!self::isValidString($token)) {
                throw new ApiRequestException('invalid parameters in getSessionState()');
            }
            $params = $this->getDefaultParams();
            $params['token'] = htmlspecialchars(trim($token));
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $params['http_user_agent'] = $_SERVER['HTTP_USER_AGENT'];
            }
            if (isset($_SERVER['REMOTE_ADDR'])) {
                $params['remote_addr'] = $_SERVER['REMOTE_ADDR'];
            }
            return $this->apiCall($params, 'get_session_state');
        }

        /**
         * Do API call
         *
         * @param array $params TBD
         *
         * @return array
         * @throws ApiRequestException
         */
        public function apiCall($params, $operation)
        {
            $json_request = json_encode($params);
            // validate request
            if (!self::isValidJSON($json_request)) {
                throw new ApiRequestException('invalid parameters in apiCall()');
            }
            // Encrypt plain text JSON string
            $encrypted_request = $this->crypto->encrypt_json($json_request);
            //print_r($encrypted_request);
            // Send request with encrypted content
            $url = $this->getApiUrl() . $operation . '/';
            $response = CurlRequest::post($url, $encrypted_request);
            // Validate response
            if (!$response || empty($response)) {
                throw new ApiRequestException('Empty response');
            }
            if (!self::isValidJSON($response)) {
                throw new ApiRequestException('Data format error: ' . $response);
            }
            // Serialize response JSON string to array
            $response = json_decode($response, true);
            // Validate array for required fields
            if (!isset($response['payload']) || !isset($response['signature'])) {
                throw new ApiRequestException('Missing encrypted fields');
            }
            // Decrypt from array
            $response = $this->crypto->decrypt_json($response);
            // validate decoded response
            if (!is_array($response) || !isset($response['success'])) {
                throw new ApiRequestException('Invalid response content: ' . $response);
            }
            // force error code from server in case of failure
            if (($response['success']) != true && !isset($response['error'])) {
                throw new ApiRequestException('Invalid response content: ' . $response);
            }
            // return result
            return $response;
        }

        /**
         * Returns the default request parameters
         *
         * @param string $function TBD
         *
         * @return array
         */
        public function getDefaultParams()
        {
            $params = array();
            $params['timestamp'] = time();
            return $params;
        }

        /**
         * Validates a json input
         *
         * @param string $data The input data to validate
         *
         * @return bool
         */
        public static function isValidJSON($data)
        {
            return is_string($data) && is_array(json_decode($data, true));
        }

        /**
         * Validates a json input
         *
         * @param string $data The input data to validate
         *
         * @return bool
         */
        public static function isValidString($data)
        {
            if (is_string($data)) {
                $data = trim($data);
            }
            return isset($data) && is_string($data) && !empty($data);
        }

        /**
         * Returns a fixed length (128) secure random token
         *
         * @return string
         */
        public static function getRandomToken()
        {
            return \GBM\ApiCrypto::randomString(64);
        }

        /**
         * Returns whether the current request made by Ajax
         *
         * @return bool
         */
        public static function isAjax()
        {
            $result = isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
            return $result;
        }
    }
}
