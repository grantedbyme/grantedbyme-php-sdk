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

        public static $TOKEN_ACCOUNT = 1;
        public static $TOKEN_SESSION = 2;
        public static $TOKEN_ACTIVATE = 4;

        ////////////////////////////////////////
        // Private Variables
        ////////////////////////////////////////

        /**
         * ServiceKey string
         *
         * @var string
         * @access private
         */
        private $service_key;

        /**
         * Config object
         *
         * @var array
         * @access private
         */
        private $config;

        /**
         * Crypto instance
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
         * Initiate key exchange for encrypted communication.
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
         * Active pending service using service key.
         *
         * @param string $service_key The activation service key
         *
         * @return array
         * @throws ApiRequestException
         */
        public function activateService($service_key)
        {
            if (!self::isValidString($service_key)) {
                throw new ApiRequestException('invalid parameters in activateService()');
            }
            // sanitize
            $service_key = htmlspecialchars(trim($service_key));
            // set service key for default headers
            $this->service_key = $service_key;
            // generate RSA key pair
            $keypair = $this->crypto->generateKeyPair();
            $handshake = $this->activateHandshake($keypair['public_key']);
            // set default headers
            $params = $this->getParams();
            $params['service_key'] = $service_key;
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
         * Deactivates a service for reactivation.
         *
         * @return array
         */
        public function deactivateService()
        {
            $params = $this->getParams();
            return $this->apiCall($params, 'deactivate_service');
        }

        /**
         * Links a service user account with a GrantedByMe account.
         *
         * @param string $challenge The challenge used to verify the user
         * @param string $authenticator_secret The secret used for user authentication
         *
         * @return array
         * @throws ApiRequestException
         */
        public function linkAccount($challenge, $authenticator_secret)
        {
            if (!self::isValidString($challenge) || !self::isValidString($authenticator_secret)) {
                throw new ApiRequestException('invalid parameters in linkAccount()');
            }
            $params = $this->getParams();
            $params['challenge'] = $challenge;
            $params['authenticator_secret'] = $authenticator_secret;
            return $this->apiCall($params, 'link_account');
        }

        /**
         * Un-links a service user account with a GrantedByMe account.
         *
         * @param string $authenticator_secret The secret used for user authentication
         *
         * @return array
         * @throws ApiRequestException
         */
        public function unlinkAccount($authenticator_secret)
        {
            if (!self::isValidString($authenticator_secret)) {
                throw new ApiRequestException('invalid parameters in unlinkAccount()');
            }
            $params = $this->getParams();
            $params['authenticator_secret'] = $authenticator_secret;
            return $this->apiCall($params, 'unlink_account');
        }

        /**
         * Returns a challenge with required type.
         *
         * @param int $challenge_type The type of requested challenge
         * @return array
         * @throws ApiRequestException
         */
        public function getChallenge($challenge_type)
        {
            $params = $this->getExtendedParams();
            $params['challenge_type'] = $challenge_type;
            return $this->apiCall($params, 'get_challenge');
        }

        /**
         * @deprecated Use getChallenge
         */
        public function getToken($challenge_type)
        {
            return $this->getChallenge($challenge_type);
        }

        /**
         * Returns a challenge state.
         *
         * @param string $challenge The challenge to check
         *
         * @return array
         * @throws ApiRequestException
         */
        public function getChallengeState($challenge)
        {
            if (!self::isValidString($challenge)) {
                throw new ApiRequestException('invalid parameters in getChallengeState()');
            }
            $params = $this->getExtendedParams();
            $params['challenge'] = $challenge;
            return $this->apiCall($params, 'get_challenge_state');
        }

        /**
         * @deprecated Use getChallengeState
         */
        public function getTokenState($challenge)
        {
            return $this->getChallengeState($challenge);
        }

        /**
         * Notify the GrantedByMe server about the user has been logged out from the service.
         *
         * @param string $challenge The challenge representing an active authentication session
         *
         * @return array
         * @throws ApiRequestException
         */
        public function revokeChallenge($challenge)
        {
            if (!self::isValidString($challenge)) {
                throw new ApiRequestException('invalid parameters in revokeChallenge()');
            }
            $params = $this->getParams();
            $params['challenge'] = $challenge;
            return $this->apiCall($params, 'revoke_challenge');
        }

        /**
         * Returns the default HTTP parameters.
         *
         * @return array
         */
        public function getParams()
        {
            $params = array();
            $params['timestamp'] = time();
            return $params;
        }

        /**
         * Returns the default HTTP parameters including IP address and User-Agent.
         *
         * @return array
         */
        public function getExtendedParams()
        {
            $params = $this->getParams();
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $params['http_user_agent'] = $_SERVER['HTTP_USER_AGENT'];
            }
            if (isset($_SERVER['REMOTE_ADDR'])) {
                $params['remote_addr'] = $_SERVER['REMOTE_ADDR'];
            }
            return $params;
        }

        /**
         * Sends a HTTP (POST) API request.
         *
         * @param array $params The request parameter object
         * @param string $operation The API operation name
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
            $plain_response = CurlRequest::post($url, $encrypted_request);
            // Validate response
            if (!$plain_response || empty($plain_response)) {
                throw new ApiRequestException('Empty response');
            }
            if (!self::isValidJSON($plain_response)) {
                throw new ApiRequestException('Data format error: ' . $plain_response);
            }
            // Serialize response JSON string to array
            $response = json_decode($plain_response, true);
            // Validate array for required fields
            if (!isset($response['payload']) || !isset($response['signature'])) {
                throw new ApiRequestException('Missing encrypted fields: ' . $plain_response);
            }
            // Decrypt from array
            $response = $this->crypto->decrypt_json($response);
            // validate decoded response
            if (!is_array($response) || !isset($response['success'])) {
                throw new ApiRequestException('Invalid response content: ' . $plain_response);
            }
            // force error code from server in case of failure
            if (($response['success']) != true && !isset($response['error'])) {
                throw new ApiRequestException('Invalid response content: ' . $plain_response);
            }
            // return result
            return $response;
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
         * Generates a secure random authenticator secret.
         *
         * @return string
         */
        public static function generateAuthenticatorSecret()
        {
            return \GBM\ApiCrypto::randomString(64);
        }

        /**
         * Generates hash digest of an authenticator secret.
         * @param string $authenticatorSecret The authenticator secret to hash
         * @return string
         */
        public static function hashAuthenticatorSecret($authenticatorSecret)
        {
            return hash('sha512', \GBM\ApiCrypto::normalizeString($authenticatorSecret));
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
