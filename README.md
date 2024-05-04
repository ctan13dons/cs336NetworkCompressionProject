# Network Compression Detection Application
This is a program that will detect if there is network compression on a network using either a cooperative or a non-cooperative approach. This is done by sending a low entropy and high entropy UDP packet train and measuring the time difference between the two. 

The cooperative approach utilizes a client and server program that is run simultaneously on two different devices residing on the same network. 

The non-cooperative approach is run on one device and "pings" another device on the same network with packets. 

*Intended for use on a Linux system*

## Part 1: Client/Server Application
### Installation
- Copy the client folder into a device on the network to be tested
- Copy the server folder into a different device on the same network

### Setup
- Run ```ip a``` on the server device, take note of the IPv4 address for the enp0s8 network interface
- On the client device, edit the config.json file with the ip address for your server device

### Execution
*The server must be run first*
On the server:
```
make
./compdetect_server
```

On the client:
```
make
./compdetect_client
```

## Part 2: Standalone Application
### Installation
- Copy the standalone folder into a device on the network to be tested
- Make sure the server device is on the same network

### Setup
- Run ```ip a``` on the server device, take note of the IPv4 address for the enp0s8 network interface
- On the client device, edit the config.json file with the ip address for your server device

### Execution 
On the client: 
```
make
sudo ./standalone
```