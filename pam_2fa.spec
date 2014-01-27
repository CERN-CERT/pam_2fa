Name:           pam_smsotp
Version:        1.4
Release:        1%{?dist}
Summary:        A Pluggable Authentication Module for SMS OTP

Group:          System Environment/Base
License:        GPLv2+
URL:            https://security.web.cern.ch
Source:		%{name}-%{version}.tgz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires:       pam
BuildRequires:  pam-devel

%description
This is pam_smsotp, a pluggable authentication module that can be used with
Linux-PAM and SMS OTP.

%prep
#(cd %{_sourcedir}; tar --exclude .git -chf - *) | tar xf -
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}/%{_lib}/security/
install -m 0755 pam_smsotp.so %{buildroot}/%{_lib}/security/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc COPYING README
/%{_lib}/security/pam_smsotp.so

%changelog
* Wed May 23 2012 Remi Mollon <Remi.Mollon@cern.ch> - 1.0
- changed packaging to be compliant to rpmlint
