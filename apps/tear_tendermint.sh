#!/bin/bash

kill -9 $(pidof tendermint)
kill -9 $(pidof java)

tendermint unsafe_reset_all
