# 2FA PAM MODULE

The PAM 2FA module provides a second factor authentication, which can be combined with the standard PAM-based password authentication to ask for:
 - What you know: user account password ( standard PAM modules )
 - What you have (pick one or more of): (PAM 2FA)
  * A TOTP Application on your phone
  * A Yubikey

## Requirement(s)

You need the following packages installed in order to properly build, install and/or use this module:
 - Redhat/CentOS/SLC6/CC7 (rpm): pam-devel, curl, curl-devel
 - Debian/Ubuntu (pkg): libpam-dev, libcurl, libcurl-dev

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

| Parameter        | Optional ? | Description | Default |
| :--------------: | :--------: | :---------- | :------ |
| debug            | Optional   | Will show every STDOUT messages in the console | |
| capath           | Optional   | Specify the path where trusted certificates are | |
| gauth_uri_prefix | Mandatory for TOTP support | Prefix of URI of the REST API for TOTP | |
| gauth_uri_suffix | Mandatory for TOTP support | Suffix of URI of the REST API for TOTP | |
| yk_uri           | Mandatory for Yubikey support | Specify the URI of the REST API for yubikey authentication | |
| domain           | Mandatory for Kerberos support | Domain used for extracting the username from kerberos principals | |
| trusted_file     | Optional   | Specify the path (relative to user home) to a trusted user list. Used for system users. If 'domain' is not NULL, principals instead of users are expected | ".k5login" |

## Required REST APIs

This PAM module delegate all the crendetial validation on remote REST APIs described here

### TOTP or "Google Authenticator"

TOTP are validated via a POST on `${gauth_uri_prefix}/${username}/${gauth_uri_suffix}` with the otp passed in the post data.
It expects 200 return code for valid OTPs and any return code >= 400 for invalid ones.

### Yubikeys

Yubikeys are validated via a POST on `${yk_uri}` with the following post data (in json):
```
{
  "username": ${username},
  "yubicode": ${otp}
}
```
It expects the raw string 'true' for valid OTPs and anything else for invalid ones

## Previous implementation

For a previous implementation of this module, using a LDAP and different endpoint, please refer to the [v1.x branch](https://github.com/CERN-CERT/pam_2fa/tree/v1.x)
