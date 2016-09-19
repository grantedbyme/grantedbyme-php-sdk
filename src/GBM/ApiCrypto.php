<?php
/**
 * Cryptography helper functions
 *
 * PHP version 5
 *
 * @category SDK
 * @package  GBM
 * @author   GrantedByMe <info@grantedby.me>
 * @access   private
 * @license  https://raw.githubusercontent.com/grantedbyme/grantedbyme-php-sdk/master/LICENSE MIT
 * @version  Release: <release_id>
 * @link     https://grantedby.me
 */
namespace GBM {

    /**
     * Cryptography helper functions
     *
     * Predefined settings:
     *
     * - RSA Encrypt/Decrypt: RSA-OAEP-MGF1-SHA1
     * - RSA Sign/Verify:     RSA-PSS-MGF1-SHA512
     * - AES:                 AES-PKCS7-CBC-256
     *
     * @category SDK
     * @package  GBM
     * @author   GrantedByMe <info@grantedby.me>
     * @access   private
     * @license  https://grantedby.me/licenses/php/license.md MIT
     * @version  Release: <release_id>
     * @link     https://grantedby.me
     */
    class ApiCrypto
    {
        ////////////////////////////////////////
        // Private Variables
        ////////////////////////////////////////

        private $rsa_public;
        private $rsa_private;
        private $aes;
        private $service_hash;
        private $config;

        ////////////////////////////////////////
        // Constructor
        ////////////////////////////////////////

        /**
         * Constructor
         *
         * @param array $config TBD
         * @throws ApiCryptoException
         */
        public function __construct($config)
        {
            // check for OpenSSL extension_loaded
            if (!extension_loaded('openssl')) {
                throw new ApiCryptoException('Missing OpenSSL extension, please enable it in php.ini');
            }
            // save config
            $this->config = $config;
            // load RSA key pair
            if ($this->config) {
                $this->loadPublicKey();
                $this->loadPrivateKey();
            }
        }

        ////////////////////////////////////////
        // Private Methods
        ////////////////////////////////////////

        /**
         * @throws ApiCryptoException
         */
        private function loadPublicKey()
        {
            if (isset($this->config) && isset($this->config['public_key'])) {
                $public_content = $this->config['public_key'];
            }
            if (!isset($public_content) || empty($public_content)) {
                return;
            }
            $rsa_public = new \phpseclib\Crypt\RSA();
            $public_load_result = $rsa_public->load($public_content);
            if ($public_load_result == false) {
                throw new ApiCryptoException('error loading public key: ' . $public_content);
            }
            $this->rsa_public = $rsa_public;
            $this->service_hash = ApiCrypto::sha512($public_content);
            // echo('public_hash: ' . $this->service_hash . '\n');
        }

        /**
         * @throws ApiCryptoException
         */
        private function loadPrivateKey()
        {
            if (isset($this->config) && isset($this->config['private_key'])) {
                $private_content = $this->config['private_key'];
            }
            if (!isset($private_content) || empty($private_content)) {
                return;
            }
            $rsa_private = new \phpseclib\Crypt\RSA();
            $private_load_result = $rsa_private->load($private_content);
            if ($private_load_result == false) {
                throw new ApiCryptoException('error loading private key: ' . $private_content);
            }
            $this->rsa_private = $rsa_private;
        }

        ////////////////////////////////////////
        // Public Methods
        ////////////////////////////////////////

        /**
         * TBD
         *
         * @return bool
         */
        public function isLoaded()
        {
            return !is_null($this->rsa_private) && !is_null($this->rsa_public);
        }

        /**
         * TBD
         *
         * @param array $config TBD
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
         * TBD
         *
         * @param string $key TBD
         * @param mixed $value TBD
         */
        public function setConfigItem($key, $value)
        {
            if (!isset($this->config)) {
                $this->config = array();
            }
            $this->config[$key] = $value;
        }

        /**
         * TBD
         *
         * @param $key
         * @return bool
         */
        public function getConfigItem($key)
        {
            if (!isset($this->config) || !isset($this->config[$key])) {
                return false;
            }
            return $this->config[$key];
        }

        /**
         * TBD
         *
         * @param string $public_key TBD
         * @throws ApiCryptoException
         */
        public function setPublicKey($public_key)
        {
            $this->setConfigItem('public_key', $public_key);
            $this->loadPublicKey();
        }

        /**
         * TBD
         *
         * @param string $private_key TBD
         * @throws ApiCryptoException
         */
        public function setPrivateKey($private_key)
        {
            $this->setConfigItem('private_key', $private_key);
            $this->loadPrivateKey();
        }

        /**
         * TBD
         *
         * @return array
         */
        public function generateKeyPair()
        {
            $rsa = new \phpseclib\Crypt\RSA();
            $key_pair = $rsa->createKey(2048);
            $public_key = (string)$key_pair['publickey'];
            $private_key = (string)$key_pair['privatekey'];
            $result = array();
            $result['private_key'] = $private_key;
            $result['public_key'] = $public_key;
            $this->setPrivateKey($private_key);
            $this->setPublicKey($public_key);
            return $result;
        }

        /**
         * @return \phpseclib\Crypt\AES
         */
        public function getAESCipher()
        {
            if (!isset($this->aes)) {
                $aes = new \phpseclib\Crypt\AES(\phpseclib\Crypt\AES::MODE_CBC);
                $this->aes = $aes;
            }
            return $this->aes;
        }

        /**
         * Encrypts an Array using signed RSA encryption and optional signed AES encryption
         * for inputs longer than the allowed RSA key space
         *
         * @param array|string $data The input array to encrypt
         * @return bool|string
         */
        public function encrypt_json($data)
        {
            if (is_array($data)) {
                $data = json_encode($data);
            }
            if(strlen($data) < 128) {
                $rsa_result = $this->encrypt_json_rsa($data);
                $result = array();
                $result['payload'] = $rsa_result['payload'];
                $result['signature'] = $rsa_result['signature'];
                $result['public_hash'] = $this->service_hash;
                return json_encode($result);
            } else {
                $aes_result = $this->encrypt_json_aes($data);
                $cipher_dict = array();
                $cipher_dict['cipher_key'] = $aes_result['key'];
                $cipher_dict['cipher_iv'] = $aes_result['iv'];
                $cipher_dict['signature'] = $aes_result['signature'];
                $cipher_dict['timestamp'] = time();
                $aes_json = json_encode($cipher_dict);
                $rsa_result = $this->encrypt_json_rsa($aes_json);
                $result = array();
                $result['payload'] = $rsa_result['payload'];
                $result['signature'] = $rsa_result['signature'];
                $result['message'] = $aes_result['message'];
                $result['public_hash'] = $this->service_hash;
                return json_encode($result);
            }

        }

        /**
         * TBD
         *
         * @param array|string $data TBD
         * @return bool|mixed
         * @throws ApiCryptoException
         */
        public function decrypt_json($data)
        {
            if (is_string($data)) {
                $data = json_decode($data, true);
            }
            $rsa_payload = base64_decode($data['payload']);
            $rsa_signature = base64_decode($data['signature']);
            $rsa_result = $this->decrypt_json_rsa($rsa_payload, $rsa_signature);
            if(!isset($data['message']) && !isset($rsa_result['cipher_key']) && !isset($rsa_result['cipher_iv'])) {
                return $rsa_result;
            }
            $cipher_key = base64_decode($rsa_result['cipher_key']);
            $cipher_iv = base64_decode($rsa_result['cipher_iv']);
            $aes_signature = base64_decode($rsa_result['signature']);
            $aes_message = base64_decode($data['message']);
            $aes_result = $this->decrypt_json_aes($aes_message, $cipher_key, $cipher_iv, $aes_signature);
            if (is_null($aes_result)) {
                return false;
            }
            return json_decode($aes_result, true);
        }

        /**
         * Encrypts and signs a JSON serialized array using RSA
         *
         * @param string $data TBD
         * @return array
         */
        public function encrypt_json_rsa($data)
        {
            if (is_array($data)) {
                $data = json_encode($data);
            }
            // encrypt
            $this->rsa_public->setHash('sha1');
            $this->rsa_public->setMGFHash('sha1');
            $encrypted_json =  $this->rsa_public->encrypt($data);
            // sign
            $this->rsa_private->setHash('sha512');
            $this->rsa_private->setMGFHash('sha512');
            $signed_json =  $this->rsa_private->sign($data);
            //echo('Source JSON: ' . $message);
            $result = array();
            $result['payload'] = base64_encode($encrypted_json);
            $result['signature'] = base64_encode($signed_json);
            return $result;
        }

        /**
         * Decrypts a JSON serialized array using RSA
         *
         * @param string $data TBD
         * @param string $signature TBD
         * @return mixed
         * @throws ApiCryptoException
         */
        public function decrypt_json_rsa($data, $signature)
        {
            // decrypt
            $this->rsa_private->setHash('sha1');
            $this->rsa_private->setMGFHash('sha1');
            $decrypted_json =  $this->rsa_private->decrypt($data);
            // verify
            $this->rsa_public->setHash('sha512');
            $this->rsa_public->setMGFHash('sha512');
            $is_valid = $this->rsa_public->verify($decrypted_json, $signature);
            if ($is_valid == false) {
                throw new ApiCryptoException('RSA signature verification failed');
            }
            //echo('Decrypted JSON: ' . $decrypted_json);
            return json_decode($decrypted_json, true);
        }

        /**
         * Encrypts a JSON serialized array using AES
         *
         * @param string $data TBD
         * @return array
         * @throws ApiCryptoException
         */
        public function encrypt_json_aes($data)
        {
            if (is_array($data)) {
                $data = json_encode($data);
            }
            $key = $this->randomString(16); // 32chr
            $iv = $this->randomString(8); // 16chr
            $aes = $this->getAESCipher();
            $aes->setKey($key);
            $aes->setIV($iv);
            $cipher_message =  $aes->encrypt($data);
            $result = array();
            $result['key'] = base64_encode($key);
            $result['iv'] = base64_encode($iv);
            $result['message'] = base64_encode($cipher_message);
            $result['signature'] = base64_encode(hash_hmac('sha256', $data, $key, true));
            return $result;
        }

        /**
         * Decrypts a JSON serialized array using AES
         *
         * @param string $data TBD
         * @param string $key TBD
         * @param string $iv TBD
         * @param string $signature TBD
         * @return string
         * @throws ApiCryptoException
         */
        public function decrypt_json_aes($data, $key, $iv, $signature)
        {
            $aes = $this->getAESCipher();
            $aes->setKey($key);
            $aes->setIV($iv);
            $result = $aes->decrypt($data);
            if($signature != hash_hmac('sha256', $result, $key, true)) {
                throw new ApiCryptoException('HMAC signature verification failed');
            }
            return $result;
        }

        //
        // STATIC
        //

        /**
         * Returns a randomized secure string by length
         *
         * @param int $len The length of string to generate
         * @return string
         */
        public static function randomString($len)
        {
            return bin2hex(\phpseclib\Crypt\Random::string($len));
        }

        /**
         * Normalize line endings
         *
         * @param string $source The input string to normalize
         * @return string
         */
        public static function normalizeString($source)
        {
            // Convert all line-endings to UNIX format
            $result = str_replace("\r\n", "\n", $source);
            $result = str_replace("\r", "\n", $result);
            // Don't allow out-of-control blank lines
            $result = preg_replace("/\n{2,}/", "\n\n", $result);
            return $result;
        }

        /**
         * Hashes a string input using SHA-512 with line ending normalization
         * @param string $source The input string to hash
         * @return string
         */
        public static function sha512($source)
        {
            return hash('sha512', \GBM\ApiCrypto::normalizeString($source));
        }
    }
}
