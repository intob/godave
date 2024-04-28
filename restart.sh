git pull
sudo cp -f $1 /etc/systemd/system/dave.service
/usr/local/go/bin/go work init godave dapi daved
cd daved && /usr/local/go/bin/go build -o bin/daved && cd ..
sudo systemctl daemon-reload
sudo systemctl enable dave.service
sudo systemctl stop dave.service
sudo systemctl start dave.service