### plaid-node quickstart

[Quickstart guide](https://plaid.com/docs/quickstart)

``` bash
git clone https://github.com/plaid/quickstart.git
cd quickstart/node
npm install

# The above call defaults to test/tartan credentials.
# Substitute other values with any of the following:

APP_PORT=8000 \
PLAID_CLIENT_ID=5ae38ebaef7f2f0010f3f607 \
PLAID_SECRET=a239e4436a3f7e8b25705b07d743f3 \
PLAID_PUBLIC_KEY=e828a5368a3da958fc99c88af1695e \
PLAID_ENV=development \
node index.js
# Go to http://localhost:8000

Step1: Click Link Account Button
Step2: Choose Your credit card institution and input user name and passcode
Step3: Click on export to S3

Step3: Copy Storage Handle and Encryption Key and keep it safe somewhere for DeSilo

```

