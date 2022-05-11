
install dependencies
```
apt-get install python3-zeroc-ice zeroc-ice-compilers python3-requests
```

enable ice and set ice secret in mumble-server.ini
```
...
ice="tcp -h 127.0.0.1 -p 6502"
icesecretwrite=changeme
...
```

copy BMauth.sample.ini to BMauth.ini and edit it
```
cp BMauth.sample.ini BMauth.ini
```

enable the systemd service
```
cp BMauth.service /etc/systemd/system/
systemctl enable BMauth.service
```

start the service
```
systemctl start BMauth.service
```

check your logs :)
