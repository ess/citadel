Summary: Help guard against certain DoS attacks.
Name: citadel
Version: 0.1.3
Release: 1
Group: System Tools/Utilities
URL: http://brokenmoon.net
License: GPLv3
Prefix: %{_prefix}
BuildRoot: %{_tmppath}/%{name}-%{version}-root
BuildArch: noarch
AutoReqProv: no
AutoReq: 0
AutoProv: 0

Requires: perl-Net-CIDR-Lite

%description
Help guard against certain DoS attacks by implementing IP blocks based on 
connection counts. Citadel is meant as a replacement for dos-deflate (ddos.sh) 
implemented in Perl.

%prep
%setup -n citadel -q -T -D

%install
rm -rf ${RPM_BUILD_ROOT}
mkdir -p ${RPM_BUILD_ROOT}/etc/cron.d
mkdir -p ${RPM_BUILD_ROOT}/etc/logrotate.d
mkdir -p ${RPM_BUILD_ROOT}/usr/local/bin
mkdir -p ${RPM_BUILD_ROOT}/etc/citadel
mkdir -p ${RPM_BUILD_ROOT}/var/log

install -m700 citadel ${RPM_BUILD_ROOT}/usr/local/bin/citadel
install -m644 citadel.cron ${RPM_BUILD_ROOT}/etc/cron.d/citadel.cron
install -m644 citadel_logrotate.d ${RPM_BUILD_ROOT}/etc/logrotate.d/citadel
install -m644 citadel.conf ${RPM_BUILD_ROOT}/etc/citadel/citadel.conf


%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%config(noreplace) /etc/citadel/citadel.conf
%config(noreplace) /etc/logrotate.d/citadel
/usr/local/bin/citadel
/etc/cron.d/citadel.cron

%post
if [ -f /var/run/crond.pid ]; then
  pid=$(cat /var/run/crond.pid)
  if [ -n ${pid} ]; then
    kill -HUP ${pid}
  fi
fi

%postun
if [ -f /var/run/crond.pid ]; then
  pid=$(cat /var/run/crond.pid)
  if [ -n ${pid} ]; then
    kill -HUP ${pid}
  fi
fi

%changelog
* Tue Dec 16 2014 Scott Sullivan <scottgregorysullivan@gmail.com> 0.1.3-1
- Allow CIDR range in allowed_ips in citadel.conf (issue#6).
* Tue Jan 21 2014 Scott Sullivan <scottgregorysullivan@gmail.com> 0.1.2-1
- Correct bug in mail sending routine, where subject and body were reversed.
- Create spool_dir if it doesn't exist. In mail send, loop on correct bad_ips.
* Wed Jan 15 2014 Scott Sullivan <scottgregorysullivan@gmail.com> 0.1.1-1
- Corrected bug in mail sending command. Require perl v5.8.8 or newer.
* Tue Jan 14 2014 Scott Sullivan <scottgregorysullivan@gmail.com> 0.1.0-1
- Initial RPM release.
