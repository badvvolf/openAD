sudo apt install libssh-dev libjson-c-dev

make
sudo cp ./build/libframework.so /usr/lib/libframework.so

ssh-keygen -t rsa -f ./ssh-honeypot.rsa

