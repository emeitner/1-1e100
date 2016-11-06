#!/bin/bash

RUN_DIR=/var/run/1-1e100

# name or UID of user that run the proxy
# may specify a numerical UID range to add additional
# users that can bypass all filtering
WHITELIST_USERS_UID="1001" #1002-1003"

GOOGLE_IP_FILE="google-ips.txt"

function usage(){
  echo -e "\n$0 [start|stop]\n\n"
}

function do_start(){
  sysctl net.ipv4.ip_forward > $RUN_DIR/net.ipv4.ip_forward
  sysctl -w net.ipv4.ip_forward=1

  ipset create googleips hash:net
  cat $GOOGLE_IP_FILE | grep -v '^#' | while read cidr; do
    echo $cidr
    ipset add googleips $cidr
  done

  iptables -A OUTPUT -m owner --uid-owner $WHITELIST_USERS_UID -j ACCEPT

  iptables -t nat -A OUTPUT -m owner ! --uid-owner $WHITELIST_USERS_UID -m set --match-set googleips dst  -p tcp --dport 443 -j REDIRECT --to-ports 4432
  iptables -t nat -A OUTPUT -m owner ! --uid-owner $WHITELIST_USERS_UID -m set --match-set googleips dst  -p tcp --dport 80 -j REDIRECT --to-ports 4432

  iptables -A OUTPUT -m set --match-set googleips dst  -j REJECT
}

function do_stop(){
  iptables -D OUTPUT -m set --match-set googleips dst  -j REJECT

  iptables -t nat -D OUTPUT -m owner ! --uid-owner $WHITELIST_USERS_UID -m set --match-set googleips dst  -p tcp --dport 80 -j REDIRECT --to-ports 4432
  iptables -t nat -D OUTPUT -m owner ! --uid-owner $WHITELIST_USERS_UID -m set --match-set googleips dst  -p tcp --dport 443 -j REDIRECT --to-ports 4432

  iptables -D OUTPUT -m owner --uid-owner $WHITELIST_USERS_UID -j ACCEPT

  if ipset -q test googleips 8.8.8.8 ; then
    ipset destroy googleips
  fi
  
  sysctl -p $RUN_DIR/net.ipv4.ip_forward
  
  [ -f $RUN_DIR/net.ipv4.ip_forward ] && rm -f $RUN_DIR/net.ipv4.ip_forward
}


if [ -z "$1" ] ; then
  usage
  exit 0
fi

case $1 in
  start)
    do_start
  ;;
  stop)
    do_stop
  ;;
  *)
    echo "Invalid option: $1"
    usage
    exit 1
  ;;
esac

exit 0
