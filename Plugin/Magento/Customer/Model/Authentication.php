<?php

namespace GetJohn\PasswordCheck\Plugin\Magento\Customer\Model;

use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Encryption\EncryptorInterface as Encryptor;
use Magento\Framework\Exception\LocalizedException;

/**
 * Class Authentication
 *
 * @package GetJohn\PasswordCheck\Plugin\Magento\Customer\Model
 */
class Authentication
{
    /**
     * @var CustomerRepositoryInterface
     */
    private $customerRepository;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    /**
     * @var Encryptor
     */
    private $encryptor;

    public function __construct(
        CustomerRepositoryInterface $customerRepository,
        Encryptor $encryptor,
        ScopeConfigInterface $scopeConfig
    ) {
        $this->customerRepository = $customerRepository;
        $this->encryptor = $encryptor;
        $this->scopeConfig = $scopeConfig;
    }

    public function afterAuthenticate(
        \Magento\Customer\Model\Authentication $subject,
        $result,
        $customerId,
        $password
    ) {
        if(!array_key_exists('password', $_POST)) return $result;

        $newPassword = $_POST['password'];
        $websitesScope = \Magento\Store\Model\ScopeInterface::SCOPE_WEBSITES;
        $preventReusingPassword = $this->scopeConfig->getValue('customer/password/prevent_reusing_password', $websitesScope);
        if($preventReusingPassword > 0) {
            $customer = $this->customerRepository->getById($customerId);
            $customAttributes = $customer->getCustomAttributes();
            $oldPasswordHashArrayJson = $customAttributes['password_history']->getValue();
            $oldPasswordHashArray = json_decode($oldPasswordHashArrayJson);
            foreach ($oldPasswordHashArray as $oldPasswordHash) {
                if ($this->encryptor->validateHash($newPassword, $oldPasswordHash)) {
                    throw new LocalizedException(
                        __("The new password was already used. Please enter another password.")
                    );
                }
            }
        }

        return $result;
    }
}
