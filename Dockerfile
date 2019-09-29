############################################################
# Dockerfile to build BlackNWhite Client container image
# Based on Ubuntu
############################################################

# Set the base image to Ubuntu
FROM ubuntu:latest

# File Author
MAINTAINER Dhruv Krishnan (dhruvkrishnan@gmail.com)

# Update the repository sources list
RUN apt-get update

################## BEGIN INSTALLATION ######################

#For Python setup
RUN apt-get install -y build-essential

#Python install
RUN apt-get install -y python-dev

#pip install
RUN apt-get install -y python-pip

#nano editor install (optional)
RUN apt-get install -y nano

#boto3 install (AWS Python API)
RUN pip install  boto3

#pycrypto install (crypto library)
RUN pip install  pycrypto

#jsonpickle install (serialization library)
RUN pip install  -U jsonpickle

#Key value store install
RUN pip install pickledb

#############################################################
