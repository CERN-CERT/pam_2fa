# 2FA PAM MODULE

The PAM 2FA module provides a second factor authentication, which can be combined with the standard PAM-based password authentication to ask for:
 - What you know: user account password ( standard PAM modules )
 - What you have (pick one of): (PAM 2FA)
  * A Google Authenticator Application on your phone
  * A Phone Number capable of receiving SMS
  * A Yubikey

## Requirement(s)

You need the following packages installed in order to properly build, install and use this module:
 - Redhat/CentOS/SLC5-6/CC7 (rpm):
  * Required:                          pam-devel
  * For LDAP support:                  openldap, openldap-devel
  * For Google Authenticator support:  curl, curl-devel
  * For Yubikey support:               ykclient, ykclient-devel (and curl, curl-devel)
 - Debian/Ubuntu (pkg)
  * Required:                          libpam-dev
  * For LDAP support:                  libldap, libldap-dev
  * For Google Authenticator support:  libcurl, libcurl-dev
  * For Yubikey support:               libykclient or libykclient3, libykclient-dev (and libcurl, libcurl-dev)

## Building

In order to BUILD the pam module and to INSTALL you need to type the following commands:
```
autoreconf -i
./configure
make
sudo make install
```
Note: You may want to use option --with-pam-dir in order to get the pam module be installed in the proper directory.


## Configuration

In order to use this PAM-2FA module you need to configure your PAM setup by adding a line to an appropriate file in /etc/pam.d/
```
        auth    required    pam_2fa.so [ PARAMETERS ]
```

### PAM+SSH Configuration

In order to use PAM-2FA module with ssh connections, you need to do the following:
 - Add the preceding line with your parameters in /etc/pam.d/sshd
 - Add the following lines to your SSHD configuration (/etc/ssh/sshd_config):
```
ChallengeResponseAuthentication yes
UsePAM yes
```
 -  Restart the SSHD daemon

### Required and supported PAM module paramaters

| Parameter       | Optional ? | Description | Default |
| :-------------: | :--------: | :---------- | :------ |
| debug           | Optional   | Will show every STDOUT messages in the console | |
| retry           | Optional   | Specify the MAX number of trials allowed to user in order to enter the 2nd factor. If the user reaches the specified number of trials, the authentication will be considered as failed | 1 |
| otp_length      | Optional   | Speficy the length of the OTP code, i.e the number of digits | 6 |
| capath          | Optional   | Speficy the path where trusted certificates are | |
| ldap_uri        | Mandatory for LDAP support | Specify the LDAP Server URI ( e.g. ldap://xldap.example.com ) | |
| ldap_attr       | Mandatory for LDAP support | Specify the attribute to search in a specific entry in order to return its value, containing the 2nd factor identity | |
| ldap_base_dn    | Mandatory for LDAP support | The Distinguished Name (DN) at which the ldap search must start in order to find the entry-ies | |
| gauth_prefix    | Optional   | Specifiy the prefix used to distinguish Google Authenticator mapping in LDAP | "GAuth:" |
| gauth_ws_uri    | Mandatory for Google Authenticator support | Specify the Google Authenticator Web Service URI | |
| gauth_ws_action | Optional   | Specify the Google Authenticator Web Service function name to check users' OTP | "CheckUser" |
| sms_prefix      | Optional   | Specify the prefix used to distinguish SMSOTP mapping in LDAP | "SMS:" |
| sms_gateway     | Mandatory for SMS OTP support | Specify the SMS gateway to which emails should be sent in order to send SMS to users | |
| sms_subject     | Optional   | Speficy the Subject field for SMS. | "" |
| sms_text        | Optional   | Specify the body and content of the message you are sending. | "Your code for authentication code is: " |
| yk_prefix       | Optional   | Specifiy the prefix used to distinguish Yubikey mapping in LDAP | "YubiKey:" |
| yk_uri          | Optional   | Specify the Yubikey server URI (if you have your internal server) | Use Yubico server pool |
| yk_id           | Mandatory for Yubikey support | Specify the client ID (see ykclient doc) | |
| yk_key          | Optional   | Set the client key (for extra client authentication against the Yubikey server) | None |
| yk_user_file    | Optional   | Specify the path (relative to user home) to the trusted yubikeys. Used when there is no LDAP support and for user 'root' | ".ssh/trusted_yubikeys" |


## SYSLOG
The PAM-2FA module will write log messages into system syslog the information about every login attempt (success or failure) and the reason of failure ( wrong code, too much retries, mobile number not found...)

You can find these log messages in the following file :
- Redhat/CentOS/SLC5-6 :      /var/log/secure
