sudo airmon-ng stop wlan1mon
sudo ip link set wlan1 down
sudo iw wlan1 set type managed
sudo systemctl start NetworkManager
