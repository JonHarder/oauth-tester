#!/bin/bash

docker compose rm -fs server
docker compose build server
docker compose up -d server
