# Cross User Secure Deduplication Proof of Concept

## This is a functional implementation, which aims to tackle the secure dedup problem.

### To build the image:
```
docker build -t IMAGE_NAME . 
```
NOTE: This build can be used to produce containers for both the client and gateway.

### To run the image:
```
docker run -it IMAGE_NAME
```

## Running the code:
### Gateway:
1. Copy the Gateway folder into your Gateway container.
2. Edit the gateway_config file to the perfrmance parameters of your choice.
3. Run the server.py file (python server.py) from inside the Gateway folder.
4. Check the ip of your Gateway container from a terminal in the host.
(docker inspect --format '{{ .NetworkSettings.IPAddress }}' CONTAINER_ID)

### Client:
1. Copy the Client folder into your Client container and enter the folder.
2. Edit the client_config file to the docker ip of the gateway container, performance parameters and AWS credentials.
3. Run the client.py file (python client.py)
4. Follow the command line.		

NOTE: Make sure you are connecting to the right docker ip.
