git pull
/usr/local/go/bin/go work init godave dapi daved
cd daved && /usr/local/go/bin/go build -o bin/daved && cd ..
sudo cp -f dave.service.conf /etc/systemd/system/dave.service
sudo systemctl daemon-reload
sudo systemctl enable dave.service
sudo systemctl stop dave.service
sudo systemctl start dave.service