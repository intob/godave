git pull
/usr/local/go/bin/go work init godave daved
cd daved && /usr/local/go/bin/go build && cd ..
sudo cp -f dave.service.conf /etc/systemd/system/dave.service
sudo systemctl daemon-reload
sudo systemctl enable dave.service
sudo systemctl stop dave.service
sudo systemctl start dave.service