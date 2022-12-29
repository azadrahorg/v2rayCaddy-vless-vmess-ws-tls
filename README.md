# V2ray Vless/Vmess + WS and TLS Installer
V2ray Vless/Vmess + WS and TLS with caddy Installer + WARP Tunnel for IPv4 and IPv6
### Prerequisites
```
1- VPS
2- Domain
```
### Install
```bash
bash -c "$(curl -L https://raw.githubusercontent.com/azadrahorg/v2rayCaddy-vless-vmess-ws-tls/main/v2rayCaddy-vless-vmess-ws-tls.sh)"
```
### Uninstall
```
bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --remove
rm /etc/apt/sources.list.d/caddy-stable.list
apt remove -y caddy
```
### Vless/Vmess
Vless to Vmess Switch
```
sed -i "s/vless/vmess/g" /usr/local/etc/v2ray/config.json
```
Vmess to Vless Switch
```
sed -i "s/vmess/vless/g" /usr/local/etc/v2ray/config.json
```
Restart v2ray after each change
```
service v2ray restart
```
