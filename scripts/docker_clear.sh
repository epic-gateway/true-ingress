#!/bin/bash

#sudo docker images | tail -n +5 | grep none | awk '{print $3}' | xargs sudo docker rmi -f
docker images | grep none | tail -n +5 | awk '{print $3}' | xargs docker rmi -f

