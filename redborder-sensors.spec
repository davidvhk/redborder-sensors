%define debug_package %{nil}

Name:           redborder-sensors
Version:        0.0.8
Release:        1%{?dist}
Summary:        Lightweight sensor sandbox for redborder

Packager:       David Vanhoucke <dvanhoucke@redborder.com>
License:        MIT
URL:            https://github.com/redBorder/redborder-sensors
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  gcc
BuildRequires:  glibc-static
BuildRequires:  systemd
Requires:       bash
Requires:       bash-completion
Requires:       iproute
Requires:       iptables
Requires:       util-linux
Requires:       wget
Requires:       procps-ng
%{?systemd_requires}

%description
This project provides a lightweight, isolated environment (sandbox) for running redborder "test sensors" using Linux namespaces. Includes chaos testing utilities and reboot persistence.

%prep
%setup -q

%build
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_libexecdir}/%{name}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/bash_completion.d

install -m 755 sensor-ctl.sh %{buildroot}%{_libexecdir}/%{name}/
install -m 755 sensor-chaos.sh %{buildroot}%{_libexecdir}/%{name}/
install -m 755 sensor-bbox.sh %{buildroot}%{_libexecdir}/%{name}/
install -m 644 redborder-sensors.service %{buildroot}%{_unitdir}/
install -m 644 sensor-ctl-completion.bash %{buildroot}%{_sysconfdir}/bash_completion.d/sensor-ctl
cp -r sensor-volume %{buildroot}%{_libexecdir}/%{name}/

ln -s %{_libexecdir}/%{name}/sensor-ctl.sh %{buildroot}%{_bindir}/sensor-ctl
ln -s %{_libexecdir}/%{name}/sensor-chaos.sh %{buildroot}%{_bindir}/sensor-chaos

%post
%systemd_post redborder-sensors.service

%preun
%systemd_preun redborder-sensors.service

%postun
%systemd_postun_with_restart redborder-sensors.service

%files
%{_bindir}/sensor-ctl
%{_bindir}/sensor-chaos
%{_libexecdir}/%{name}/
%{_unitdir}/redborder-sensors.service
%{_sysconfdir}/bash_completion.d/sensor-ctl

%changelog
* Fri Jun 12 2026 David Vanhoucke <dvanhoucke@redborder.com> - 0.0.8-1
- Improve smart path resolution for all command arguments
- Add sflow shorthand command
* Fri Jun 12 2026 David Vanhoucke <dvanhoucke@redborder.com> - 0.0.7-1
- Add bash completion support and shorthand commands
* Sun Jun 07 2026 David Vanhoucke <dvanhoucke@redborder.com> - 0.0.4-1
- Add reboot persistence and systemd service support
* Sun May 31 2026 David Vanhoucke <dvanhoucke@redborder.com> - 0.0.1-1
- Initial RPM release
