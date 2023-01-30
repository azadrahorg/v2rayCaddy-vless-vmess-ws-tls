#!/bin/bash -e
echo
echo "=== azadrah.org ==="
echo "=== https://github.com/azadrah-org ==="
echo "=== V2ray with Caddy [Vless/Vmess+WS+TLS] (Ubuntu 22.04) ==="
echo
sleep 3

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m '
cyan='\e[96m'
none='\e[0m '
_red() { echo -e ${red}$*${none}; }
_green() { echo -e ${green}$*${none}; }
_yellow() { echo -e ${yellow}$*${none}; }
_magenta () { echo -e ${magenta} $* ${none} ; }
_cyan() { echo -e ${cyan}$*${none}; }

error() {
    echo -e " \n $red input error! $none \n "
}

pause() {
    read -rsp "$(echo -e "Press$green Enter$none to continue....or$red Ctrl + C$none to cancel.")" -d $'\n'
    echo
}


function exit_badly {
  echo "$1"
  exit 1
}

if [[ dist1=$(lsb_release -rs) == "18.04" ]] || [[ dist2=$(lsb_release -rs) == "20.04" ]]; then exit_badly "This script is for Ubuntu 22.04 only: aborting (if you know what you're doing, try deleting this check)"
else
[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"
fi

#Execute the script with parameters
if [ $# -ge 1 ]; then

    #The first parameter is the domain name
    domain=${1}

    #The second parameter is on ipv4 or ipv6
    case ${2} in
    4)
        netstack=4
        ;;
    6)
        netstack=6
        ;;    
    *) # initial
        netstack="i"
        ;;    
    esac

    #The third parameter is UUID
    v2ray_id=${3}
    if [[ -z $v2ray_id ]]; then
        v2ray_id=$(cat /proc/sys/kernel/random/uuid)
    fi
        
    v2ray_port=$(shuf -i20001-65535 -n1)

    #The fourth parameter is path
    path=${4}
    if [[ -z $path ]]; then 
        path=$(echo $v2ray_id | sed 's/.*\([a-z0-9]\{12\}\)$/\1/g')
    fi

    proxy_site="https://support.microsoft.com"

    echo -e "domain: ${domain}"
    echo -e "netstack: ${netstack}"
    echo -e "v2ray_id: ${v2ray_id}"
    echo -e "v2ray_port: ${v2ray_port}"
    echo -e "path: ${path}"
    echo -e "proxy_site: ${proxy_site}"
fi

pause

echo
echo "=== Preparation ==="
echo
sleep 1


echo
echo "=== Update System ==="
echo
sleep 1

apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true install -y software-properties-common
add-apt-repository --yes universe
add-apt-repository --yes restricted
add-apt-repository --yes multiverse
apt-get -o Acquire::ForceIPv4=true install -y moreutils dnsutils tmux screen nano wget curl socat jq qrencode

echo
echo "=== Install V2ray 4.45.2 Version ==="
echo
sleep 1

bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) --version 4.45.2
systemctl enable v2ray

echo
echo "=== Install Latest Caddy ==="
echo
sleep 1

apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
apt update
apt install caddy
systemctl enable caddy

echo
echo "=== Sysctl Config ==="
echo
sleep 1

sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sed -i '/net.ipv4.tcp_fastopen /d' /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
echo "net.ipv4.tcp_fastopen = 3" >>/etc/sysctl.conf
sysctl -p >/dev/null 2>&1
echo

echo
echo "===  Confg WebSocket TLS mode  ==="
echo
sleep 1

# UUID
if [[ -z $v2ray_id ]]; then
    uuid=$(cat /proc/sys/kernel/random/uuid)
    while :; do
        echo -e "Please enter "$yellow "V2RayID"$none "  "
        read -p "$(echo -e "(ID: ${cyan}${uuid}$none):")" v2ray_id
        [ -z "$v2ray_id" ] && v2ray_id=$uuid
        case $(echo $v2ray_id | sed 's/[a-z0-9]\{8\}-[a-z0-9]\{4\}-[a-z0-9]\{4\}-[a-z0-9]\{4\}-[a-z0-9]\{12\}//g') in
        "")
            echo
            echo
            echo -e "$yellow V2Ray ID = $cyan$v2ray_id$none"
            echo "----------------------------------------------------------------"
            echo
            break
            ;;
        *)
            error
            ;;
        esac
    done
fi

# V2ray internal port
if [[ -z $v2ray_port ]]; then
    random=$(shuf -i20001-65535 -n1)
    while :; do
        echo -e "Please enter " $yellow " V2Ray " $none " port [ " $magenta " 1-65535 " $none " ], cannot choose " $magenta " 80 " $none " or " $magenta " 443 " $none " port "
        read -p "$( echo -e "(default port: ${cyan}${random} $none ):" )" v2ray_port
        [ -z "$v2ray_port" ] && v2ray_port=$random
        case $v2ray_port in
        80)
            echo
            echo  "...I said you can't choose port 80..."
            error
            ;;
        443)
            echo
            echo  "..I said you can't choose port 443..."
            error
            ;;
        [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
            echo
            echo
            echo -e "$yellow Internal V2Ray port Internal port = $cyan$v2ray_port$none"
            echo "----------------------------------------------------------------"
            echo
            break
            ;;
        *)
            error
            ;;
        esac
    done
fi

# domain name
if [[ -z $domain ]]; then
    while :; do
        echo
        echo -e "Please enter a${magenta} correct domain name${none} Input your domain"
        read -p "(eg: mydomain.com):" domain
        [ -z "$domain" ] && error && continue
        echo
        echo
        echo -e "$yellow your domain Domain =$cyan $domain $none"
        echo "----------------------------------------------------------------"
        break
    done
fi

#network stack
if [[ -z $netstack ]]; then
    echo -e "If your chick is${magenta} dual-stack (both IPv4 and IPv6 IP)${none}, please choose which 'network port' you put v2ray on"
    echo  "If you don't understand what this passage means, please press Enter"
    read -p "$(echo -e "Input ${cyan}4${none} for IPv4, ${cyan}6${none} for IPv6:")" netstack
    if [[ $netstack == "4" ]]; then
        domain_resolve=$(curl -sH 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$domain&type=A" | jq -r '.Answer[0].data')
    elif [[ $netstack == "6" ]]; then 
        domain_resolve=$(curl -sH 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$domain&type=AAAA" | jq -r '.Answer[0].data')
    else
        domain_resolve=$(curl -sH 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$domain&type=A" | jq -r '.Answer[0].data')
        if [[ "$domain_resolve" != "null" ]]; then
            netstack="4"
        else
            domain_resolve=$(curl -sH 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$domain&type=AAAA" | jq -r '.Answer[0].data')            
            if [[ "$domain_resolve" != "null" ]]; then
                netstack="6"
            fi
        fi
    fi

    #Local IP
    if [[ $netstack == "4" ]]; then
        ip=$(curl -4 -s https://api.myip.la | jq -r '.ip')
    elif [[ $netstack == "6" ]]; then 
        ip=$(curl -6 -s https://api.myip.la | jq -r '.ip')
    else
        ip=$(curl -s https://api.myip.la | jq -r '.ip')
    fi

    if [[ $domain_resolve != $ip ]]; then
        echo
        echo -e "$red domain name resolution error Domain resolution error....$none"
        echo
        echo -e "Your domain name:$yellow$domain$none did not resolve to:$cyan$ip$none"
        echo
        if [[ $domain_resolve != "null" ]]; then
            echo -e "Your domain name is currently resolved to:$cyan$domain_resolve$none"
        else
            echo -e "Domain not resolved$none detected by $red" 
        fi
        echo
        echo -e " Remarks... If your domain name is resolved using$yellow Cloudflare$none ... On the DNS settings page, please set$yellow proxy status$none to$yellow DNS only$none , and Xiao Yunduo becomes gray."
        echo "Notice...If you use Cloudflare to resolve your domain, on 'DNS' setting page, 'Proxy status' should be 'DNS only' but not 'Proxied'."
        echo
        exit 1
    else
        echo
        echo
        echo -e "$yellow domain name resolution =${cyan} I'm sure$none has already been resolved"
        echo "----------------------------------------------------------------"
        echo
    fi
fi

#Split path
if [[ -z $path ]]; then
    default_path=$(echo $v2ray_id | sed 's/.*\([a-z0-9]\{12\}\)$/\1/g')
    while :; do
        echo -e "Please enter the path$none that you want${magenta} to use for distribution , such as /v2raypath, then you only need to enter v2raypath"
        echo "Input the WebSocket path for V2ray"
        read -p "$(echo -e "(path: [${cyan}${default_path}$none]):")" path
        [[ -z $path ]] && path=$default_path

        case  $path  in
        *[/$]*)
            echo
            echo -e "Because this script is too spicy.. so the distribution path cannot contain the two symbols $red / $none or $red $ $none ...."
            echo
            error
            ;;
        *)
            echo
            echo
            echo -e "Path of$yellow shunt = ${cyan}/${path} $none"
            echo "----------------------------------------------------------------"
            echo
            break
            ;;
        esac
    done
fi

# anti-generation camouflage website
if [[ -z $proxy_site ]]; then
    while :; do
        echo -e "Please enter${magenta} a correct$none ${cyan} URL$none is used as a$none disguise for${cyan} website , such as https://support.microsoft.com"
        echo "Input a camouflage site. When IRFW visit your domain, the camouflage site will display."
        read -p "$(echo -e "(site: [${cyan}https://support.microsoft.com${none}]):")" proxy_site
        [[ -z $proxy_site ]] && proxy_site="https://support.microsoft.com"

        case $proxy_site in
        *[#$]*)
            echo
            echo -e "Because this script is too spicy.. so the disguised URL cannot contain the two symbols $red # $none or $red $ $none ...."
            echo
            error
            ;;
        *)
            echo
            echo
            echo -e "$yellow camouflage site =${cyan}${proxy_site}$none"
            echo "----------------------------------------------------------------"
            echo
            break
            ;;
        esac
    done
fi

# Configuration/usr/local/etc/v2ray/config.json
echo
echo -e "$yellow config/usr/local/etc/v2ray/config.json$none"
echo "----------------------------------------------------------------"
cat >/usr/local/etc/v2ray/config.json <<-EOF
{ // vless + WebSocket + TLS
    "log": {
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "listen": "127.0.0.1",
            "port": $v2ray_port,             // ***
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$v2ray_id",             // ***
                        "level": 1,
                        "alterId": 0
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        // [inbound] If you comment out the following paragraph, then also comment out the English comma at the end of the above line
        {
            "listen":"127.0.0.1",
            "port":1080,
            "protocol":"socks",
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls"
                ]
            },
            "settings":{
                "auth":"noauth",
                "udp":false
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIP"
            },
            "tag": "direct"
        },
        // [outbound]
{
    "protocol": "freedom",
    "settings": {
        "domainStrategy": "UseIPv4"
    },
    "tag": "force-ipv4"
},
{
    "protocol": "freedom",
    "settings": {
        "domainStrategy": "UseIPv6"
    },
    "tag": "force-ipv6"
},
{
    "protocol": "socks",
    "settings": {
        "servers": [{
            "address": "127.0.0.1",
            "port": 40000 //warp socks5 port
        }]
     },
    "tag": "socks5-warp"
},
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "dns": {
        "servers": [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "localhost"
        ]
    },
    "routing": {
        "domainStrategy": "IPOnDemand",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "0.0.0.0/8",
                    "10.0.0.0/8",
                    "100.64.0.0/10",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "172.16.0.0/12",
                    "192.0.0.0/24",
                    "192.0.2.0/24",
                    "192.168.0.0/16",
                    "198.18.0.0/15",
                    "198.51.100.0/24",
                    "203.0.113.0/24",
                    "::1/128",
                    "fc00::/7",
                    "fe80::/10"
                ],
                "outboundTag": "blocked"
            },
            // [routing-rule]
//{
//     "type": "field",
//     "domain": ["geosite:google"],  // ***
//     "outboundTag": "force-ipv6"  // force-ipv6 // force-ipv4 // socks5-warp
//},
//{
//     "type": "field",
//     "domain": ["geosite:ir"],  // ***
//     "outboundTag": "force-ipv6"  // force-ipv6 // force-ipv4 // socks5-warp // blocked
//},
//{
//     "type": "field",
//     "ip": ["geoip:ir"],  // ***
//     "outboundTag": "force-ipv6"  // force-ipv6 // force-ipv4 // socks5-warp // blocked
//},
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF

#place /etc/caddy/Caddyfile
echo
echo -e "$yellow /etc/caddy/Caddyfile$none"
echo "----------------------------------------------------------------"
cat >/etc/caddy/Caddyfile <<-EOF
$domain
{
    tls 3g8wehag@duck.com
    encode gzip
# multi-user multi-path
#    import Caddyfile.multiuser
    handle_path /$path {
        reverse_proxy localhost:$v2ray_port
    }
    handle {
        reverse_proxy $proxy_site {
            trusted_proxies 0.0.0.0/0
            header_up Host {upstream_hostport}
        }
    }
}
EOF

#Multiple users and multiple paths
multiuser_path=""
user_number=10
while [ $user_number -gt 0 ]; do
    random_path=$(cat /proc/sys/kernel/random/uuid | sed 's/.*\([a-z0-9]\{4\}-[a-z0-9]\{12\}\)$/\1/g')

    multiuser_path=${multiuser_path}"path /"${random_path}$'\n'

    user_number=$(($user_number - 1))
done

cat >/etc/caddy/Caddyfile.multiuser <<-EOF
@ws_path {
$multiuser_path
}
handle @ws_path {
    uri path_regexp /.* /
    reverse_proxy localhost:$v2ray_port
}
EOF

#Restart V2Ray
echo
echo -e "$yellow restart V2Ray$none"
echo "----------------------------------------------------------------"
rm -rf /usr/local/share/v2ray/geoip.dat
curl -L https://github.com/SamadiPour/iran-hosted-domains/releases/download/202212202154/iran.dat -o /usr/local/share/v2ray/geoip.dat
service v2ray restart

#Restart CaddyV2
echo
echo -e "$yellow restart CaddyV2$none"
echo "----------------------------------------------------------------"
service caddy restart

echo
echo
echo  "---------- V2Ray configuration information-------------"
echo -e "$green --- hint..this is the VLESS server configuration --- $none "
echo -e "$yellow Domain (Address) = $cyan${domain}$none"
echo -e "$yellow port (Port) = ${cyan} 443 ${none} "
echo -e "$yellow ID (User ID / UUID) = $cyan${v2ray_id}$none"
echo -e "$yellow flow control (Flow) = ${cyan} empty ${none} "
echo -e "$yellow Security (Encryption) = ${cyan}none${none}"
echo -e "$yellow Transport Protocol(Network) = ${cyan} ws $none "
echo -e "$yellow masquerade type (header type) = ${cyan} none $none "
echo -e "$yellow masquerade domain name (host) = ${cyan}${domain} $none "
echo -e "$yellow Path (path) = ${cyan}/${path}$none"
echo -e "$yellow TLS = ${cyan} tls $none "
echo
echo "---------- V2Ray VLESS URL ----------"
v2ray_vless_url="vless://${v2ray_id}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${path}#VLESS_WSS_${domain}"
echo -e "${cyan}${v2ray_vless_url}${none}"
echo
sleep 3
echo  "The following two QR codes have exactly the same content"
qrencode -t UTF8 $v2ray_vless_url
echo "-------------------------------------"
qrencode -t ANSI $v2ray_vless_url
echo
echo "---------- END -------------"
echo  "The above node information is saved in ~/_v2ray_vless_url_ "

# Save the node information to the file
echo $v2ray_vless_url > ~/_v2ray_vless_url_
echo  " The following two QR codes have exactly the same content "  >>  ~ /_v2ray_vless_url_
qrencode -t UTF8 $v2ray_vless_url >> ~/_v2ray_vless_url_
qrencode -t ANSI $v2ray_vless_url >> ~/_v2ray_vless_url_

echo
echo "=== Change to Vmess ==="
echo
sleep 1

#Whether to switch to vmess protocol
echo 
echo -e "Switch to${magenta} Vmess${none} protocol?"
echo  "If you don't understand what this message means, please press Enter"
read -p "$(echo -e "(${cyan}y/N${none} Default No):") " switchVmess
if [[ -z "$switchVmess" ]]; then
    switchVmess='N'
fi
if [[ "$switchVmess" == [yY] ]]; then
    # In the config.json file, replace vless with vmess
    sed -i "s/vless/vmess/g" /usr/local/etc/v2ray/config.json
    service v2ray restart
    
    #Generate vmess link and QR code
    echo "---------- V2Ray Vmess URL ----------"
    v2ray_vmess_url="vmess://$(echo -n "\
{\
\"v\": \"2\",\
\"ps\": \"Vmess_WSS_${domain}\",\
\"add\": \"${domain}\",\
\"port\": \"443\",\
\"id\": \"${v2ray_id}\",\
\"aid\": \"0\",\
\"net\": \"ws\",\
\"type\": \"none\",\
\"host\": \"${domain}\",\
\"path\": \"${path}\",\
\"tls\": \"tls\"\
}"\
    | base64 -w 0)"

    echo -e "${cyan}${v2ray_vmess_url}${none}"
    echo  "The following two QR codes have exactly the same content"
    qrencode -t UTF8 $v2ray_vmess_url
    qrencode -t ANSI $v2ray_vmess_url

    echo
    echo "---------- END -------------"
    echo  "The above node information is saved in ~/_v2ray_vmess_url_"

    echo $v2ray_vmess_url > ~/_v2ray_vmess_url_
    echo  "The following two QR codes have exactly the same content"  >>  ~ /_v2ray_vmess_url_
    qrencode -t UTF8 $v2ray_vmess_url >> ~/_v2ray_vmess_url_
    qrencode -t ANSI $v2ray_vmess_url >> ~/_v2ray_vmess_url_
    
elif [[ "$switchVmess" == [nN] ]]; then
    echo
else
    error
fi

echo
echo "=== IPv6 Tunnel to IPv4 ==="
echo
sleep 1

# If IPv6 , create IPv4 outbound with WARP
if [[ $netstack == "6" ]]; then
    echo
    echo -e "$yellow this is an IPv6 , create IPv4 outbound with WARP $none"
    echo  "Telegram accesses IPv4 addresses directly, and requires IPv4 outbound capabilities"
    echo "----------------------------------------------------------------"
    pause

    # install warp ipv4
    bash <(curl -L git.io/warp.sh) 4

    #Restart V2Ray
    echo
    echo -e "$yellow restart V2Ray $none"
    echo "----------------------------------------------------------------"
    service v2ray restart

    #Restart CaddyV2
    echo
    echo -e "$yellow restart CaddyV2 $none"
    echo "----------------------------------------------------------------"
    service caddy restart

echo
echo "=== IPv4 Tunnel for IPv6 ==="
echo
sleep 1

# If IPv4 , create IPv6 outbound with WARP
elif  [[ $netstack == "4" ]]; then
    echo
    echo -e "$yellow This is an IPv4 , create IPv6 outbound with WARP $none"
    echo -e "Some popular s use native IPv4 outbound to access Google and need to pass man-machine verification, which can be solved by modifying config.json to specify that google traffic go through WARP's IPv6 outbound"
    echo "----------------------------------------------------------------"
    pause

    # install warp ipv6
    bash <(curl -L git.io/warp.sh) 6

    #Restart V2Ray
    echo
    echo -e "$yellow restart V2Ray $none"
    echo "----------------------------------------------------------------"
    service v2ray restart

    #Restart CaddyV2
    echo
    echo -e "$yellow restart CaddyV2 $none"
    echo "----------------------------------------------------------------"
    service caddy restart

fi

echo
echo "=== Finished ==="
echo
sleep 1
