git pull
cd daved && go build
sudo cp -f dave.service.conf /etc/systemd/system/dave.service
sudo systemctl daemon-reload
sudo systemctl enable dave.service
sudo systemctl stop dave.service
sudo systemctl start dave.service