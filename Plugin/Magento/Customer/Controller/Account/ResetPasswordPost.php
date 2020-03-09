<?php

namespace GetJohn\PasswordCheck\Plugin\Magento\Customer\Controller\Account;

use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Model\CustomerRegistry;
use Magento\Customer\Model\ForgotPasswordToken\GetCustomerByToken;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Config\ScopeConfigInterface;

/**
 * Class ResetPasswordPost
 *
 * @package GetJohn\PasswordCheck\Plugin\Magento\Customer\Controller\Account
 */
class ResetPasswordPost
{
    /**
     * @var Session
     */
    protected $session;

    /**
     * @var CustomerRepositoryInterface
     */
    protected $customerRepository;

    /**
     * @var CustomerRegistry
     */
    private $customerRegistry;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    /**
     * @var GetCustomerByToken
     */
    private $getByToken;

    public function __construct(
        Session $customerSession,
        CustomerRepositoryInterface $customerRepository,
        CustomerRegistry $customerRegistry,
        ScopeConfigInterface $scopeConfig,
        GetCustomerByToken $getByToken
    ) {
        $this->session = $customerSession;
        $this->customerRepository = $customerRepository;
        $this->customerRegistry = $customerRegistry;
        $this->scopeConfig = $scopeConfig;
        $this->getByToken = $getByToken;
    }

    public function beforeExecute(
        \Magento\Customer\Controller\Account\ResetPasswordPost $subject
    ) {
        $websitesScope = \Magento\Store\Model\ScopeInterface::SCOPE_WEBSITES;
        $preventReusingPassword = $this->scopeConfig->getValue('customer/password/prevent_reusing_password', $websitesScope);
        if($preventReusingPassword > 0) {
            $resetPasswordToken = (string)$subject->getRequest()->getQuery('token');
            $customer = $this->getByToken->execute($resetPasswordToken);
            $this->session->setCustomerId($customer->getId());
            $customAttributes = $customer->getCustomAttributes();
            if (!array_key_exists('password_history', $customAttributes)) {
                $customerSecure = $this->customerRegistry->retrieveSecureData($customer->getId());
                $currentPasswordHash = $customerSecure->getPasswordHash();
                $passwordHashArrayJson = json_encode(array($currentPasswordHash));

                $extensionAttributes = $customer->getExtensionAttributes();
                $extensionAttributes->setData('password_history', $passwordHashArrayJson);
                $customer->setExtensionAttributes($extensionAttributes);
                $this->customerRepository->save($customer);
            } else {
                $oldPasswordHashArrayJson = $customAttributes['password_history']->getValue();
                $oldPasswordHashArray = json_decode($oldPasswordHashArrayJson);
                if(count($oldPasswordHashArray) > $preventReusingPassword) {
                    $x = count($oldPasswordHashArray) - $preventReusingPassword;
                    $oldPasswordHashArrayNew = array_slice($oldPasswordHashArray, $x);
                    $passwordHashArrayJson = json_encode($oldPasswordHashArrayNew);

                    $extensionAttributes = $customer->getExtensionAttributes();
                    $extensionAttributes->setData('password_history', $passwordHashArrayJson);
                    $customer->setExtensionAttributes($extensionAttributes);
                    $this->customerRepository->save($customer);
                }
            }
        }

        return [];
    }

    public function afterExecute(
        \Magento\Customer\Controller\Account\ResetPasswordPost $subject,
        $result
    ) {
        $websitesScope = \Magento\Store\Model\ScopeInterface::SCOPE_WEBSITES;
        $preventReusingPassword = $this->scopeConfig->getValue('customer/password/prevent_reusing_password', $websitesScope);
        if($preventReusingPassword > 0) {
            $customer = $this->customerRepository->getById($this->session->getCustomerId());
            $this->session->unsCustomerId();
            $customerSecure = $this->customerRegistry->retrieveSecureData($customer->getId());
            $currentPasswordHash = $customerSecure->getPasswordHash();
            $customAttributes = $customer->getCustomAttributes();
            $alreadyUsedFlag = false;
            $oldPasswordHashArrayJson = $customAttributes['password_history']->getValue();
            $oldPasswordHashArray = json_decode($oldPasswordHashArrayJson);
            foreach ($oldPasswordHashArray as $oldPasswordHash) {
                if ($oldPasswordHash == $currentPasswordHash) {
                    $alreadyUsedFlag = true;
                    break;
                }
            }

            if (!$alreadyUsedFlag) {
                array_push($oldPasswordHashArray, $currentPasswordHash);
                $passwordHashArrayJson = json_encode($oldPasswordHashArray);

                $extensionAttributes = $customer->getExtensionAttributes();
                $extensionAttributes->setData('password_history', $passwordHashArrayJson);
                $extensionAttributes->setData('password_last_changed_date', date('Y-m-d H:i:s'));
                $customer->setExtensionAttributes($extensionAttributes);
                $this->customerRepository->save($customer);
            }
        }

        return $result;
    }
}
