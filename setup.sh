#!/bin/bash


function usage(){
  echo -e "\n$0 [start|stop]\n\n"
}

function do_start(){

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

}


if [ -f setup.cfg ] ; then
  . setup.cfg
elif [ -f `dirname $0`/setup.cfg ]; then
  . `dirname $0`/setup.cfg
else
  echo
  echo "Can't find configuration file setup.cfg."
  exit 0
fi

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
