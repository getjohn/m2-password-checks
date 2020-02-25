# Mage2 Module GetJohn PasswordCheck

    "getjohn/module-passwordcheck"

 - [Main Functionalities](#markdown-header-main-functionalities)
 - [Installation](#markdown-header-installation)
 - [Configuration](#markdown-header-configuration)
 - [Specifications](#markdown-header-specifications)
 - [Attributes](#markdown-header-attributes)


## Main Functionalities


## Installation
\* = in production please use the `--keep-generated` option

### Type 1: Zip file

 - Unzip the zip file in `app/code/GetJohn`
 - Enable the module by running `php bin/magento module:enable GetJohn_PasswordCheck`
 - Apply database updates by running `php bin/magento setup:upgrade`\*
 - Flush the cache by running `php bin/magento cache:flush`

### Type 2: Composer

 - Make the module available in a composer repository for example:
    - private repository `repo.magento.com`
    - public repository `packagist.org`
    - public github repository as vcs
 - Add the composer repository to the configuration by running `composer config repositories.repo.magento.com composer https://repo.magento.com/`
 - Install the module composer by running `composer require getjohn/module-passwordcheck`
 - enable the module by running `php bin/magento module:enable GetJohn_PasswordCheck`
 - apply database updates by running `php bin/magento setup:upgrade`\*
 - Flush the cache by running `php bin/magento cache:flush`


## Configuration

 - Prevent Re-using Last X Passwords (customer/password/prevent_reusing_password)

 - Enforce Password Reset Every X Days (customer/password/enforce_password_reset)
 
 - X Days (customer/password/x_days)


## Specifications

 - Plugin
 	- beforeExecute - Magento\Customer\Controller\Account\EditPost > GetJohn\PasswordCheck\Plugin\Magento\Customer\Controller\Account\EditPost
 	
 - Plugin
  	- afterExecute - Magento\Customer\Controller\Account\EditPost > GetJohn\PasswordCheck\Plugin\Magento\Customer\Controller\Account\EditPost

 - Plugin
 	- beforeExecute - Magento\Customer\Controller\Account\ResetPasswordPost > GetJohn\PasswordCheck\Plugin\Magento\Customer\Controller\Account\ResetPasswordPost
 	
 - Plugin
  	- afterExecute - Magento\Customer\Controller\Account\ResetPasswordPost > GetJohn\PasswordCheck\Plugin\Magento\Customer\Controller\Account\ResetPasswordPost

 - Plugin
	- afterAuthenticate - Magento\Customer\Model\AccountManagement > GetJohn\PasswordCheck\Plugin\Magento\Customer\Model\AccountManagement

 - Plugin
	- beforeChangePassword - Magento\Customer\Model\AccountManagement > GetJohn\PasswordCheck\Plugin\Magento\Customer\Model\AccountManagement
	
 - Plugin
	- beforeResetPassword - Magento\Customer\Model\AccountManagement > GetJohn\PasswordCheck\Plugin\Magento\Customer\Model\AccountManagement


## Attributes

 - Customer - Password History (password_history)

 - Customer - Password Last Changed Date (password_last_changed_date) 

