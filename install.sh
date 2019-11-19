
sudo apt-get install libssh-dev libjson-c-dev
sudo apt-get install libc6-dev-i386
sudo apt-get install libelf-dev
sudo apt-get install clang


git submodule init
git submodule update

cd ./libbpf/src
make
sudo cp libbpf.so /usr/lib/.
sudo cp libbpf.so.0 /usr/lib/.
cp libbpf.so ../../lib/.
cp libbpf.a ../../lib/.
cd ../../

make
sudo cp ./build/libframework.so /usr/lib/.

ssh-keygen -t rsa -f ./ssh-honeypot.rsa

