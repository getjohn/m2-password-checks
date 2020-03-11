<?php

namespace GetJohn\PasswordCheck\Plugin\Magento\Customer\Model;

use DateTime;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Model\ForgotPasswordToken\GetCustomerByToken;
use Magento\Framework\Encryption\EncryptorInterface as Encryptor;
use Magento\Framework\Exception\InputException;
use Magento\Framework\Exception\SecurityViolationException;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Message\ManagerInterface;
use Magento\Framework\Escaper;

/**
 * Class AccountManagement
 *
 * @package GetJohn\PasswordCheck\Plugin\Magento\Customer\Model
 */
class AccountManagement
{
    /**
     * @var CustomerRepositoryInterface
     */
    private $customerRepository;

    /**
     * @var Encryptor
     */
    private $encryptor;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    /**
     * @var ManagerInterface
     */
    private $messageManager;

    /**
     * @var \Magento\Framework\Escaper
     */
    protected $escaper;

    /**
     * @var GetCustomerByToken
     */
    private $getByToken;

    public function __construct(
        CustomerRepositoryInterface $customerRepository,
        Encryptor $encryptor,
        ScopeConfigInterface $scopeConfig,
        ManagerInterface $messageManager,
        Escaper $escaper,
        GetCustomerByToken $getByToken
    ) {
        $this->customerRepository = $customerRepository;
        $this->encryptor = $encryptor;
        $this->scopeConfig = $scopeConfig;
        $this->messageManager = $messageManager;
        $this->escaper = $escaper;
        $this->getByToken = $getByToken;
    }

    public function afterAuthenticate(
        \Magento\Customer\Model\AccountManagement $subject,
        $result,
        $username,
        $password
    ) {
        $websitesScope = \Magento\Store\Model\ScopeInterface::SCOPE_WEBSITES;
        $enforcePasswordReset = $this->scopeConfig->getValue('customer/password/enforce_password_reset', $websitesScope);
        if($enforcePasswordReset > 0) {
            $customer = $result;
            $customAttributes = $customer->getCustomAttributes();
            if (!array_key_exists('password_last_changed_date', $customAttributes)) {
                $lastUpdatedDate = $customer->getCreatedAt();
            } else {
                $lastUpdatedDate = $customAttributes['password_last_changed_date']->getValue();
            }

            $today = new DateTime('now');
            $lastUpdatedDate = new DateTime($lastUpdatedDate);
            $interval = date_diff($today, $lastUpdatedDate)->format('%a');
            $xDays = $enforcePasswordReset;
            if ($interval >= $xDays) {
                try {
                    $subject->initiatePasswordReset(
                        $customer->getEmail(),
                        \Magento\Customer\Model\AccountManagement::EMAIL_RESET
                    );
                } catch (SecurityViolationException $exception) {
                    $this->messageManager->addErrorMessage($exception->getMessage());
                } catch (\Exception $exception) {
                    $this->messageManager->addExceptionMessage(
                        $exception,
                        __('We\'re unable to send the password reset email.')
                    );
                }
                $this->messageManager->addWarningMessage($this->getSuccessMessage($customer->getEmail()));
            }
        }

        return $result;
    }

    public function beforeResetPassword(
        \Magento\Customer\Model\AccountManagement $subject,
        $email,
        $resetToken,
        $newPassword
    ) {
        $websitesScope = \Magento\Store\Model\ScopeInterface::SCOPE_WEBSITES;
        $preventReusingPassword = $this->scopeConfig->getValue('customer/password/prevent_reusing_password', $websitesScope);
        if($preventReusingPassword > 0) {
            if (!$email) {
                $customer = $this->getByToken->execute($resetToken);
            } else {
                $customer = $this->customerRepository->get($email);
            }

            $customAttributes = $customer->getCustomAttributes();
            $oldPasswordHashArrayJson = $customAttributes['password_history']->getValue();
            $oldPasswordHashArray = json_decode($oldPasswordHashArrayJson);
            foreach ($oldPasswordHashArray as $oldPasswordHash) {
                if ($this->encryptor->validateHash($newPassword, $oldPasswordHash)) {
                    throw new InputException(
                        __("The new password was already used. Please enter another password.")
                    );
                }
            }
        }

        return [$email, $resetToken, $newPassword];
    }

    /**
     * Retrieve success message
     *
     * @param string $email
     * @return \Magento\Framework\Phrase
     */
    protected function getSuccessMessage($email)
    {
        return __(
            'Your password was too old. You will receive an email with a link to reset your password on %1. Please reset your password.',
            $this->escaper->escapeHtml($email)
        );
    }
}

