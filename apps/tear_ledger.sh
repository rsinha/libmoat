echo "Killing ledgerservice..."
kill -9 $(pidof java)

cd ledgerservice/artifacts && ./byfn.sh -m down 
