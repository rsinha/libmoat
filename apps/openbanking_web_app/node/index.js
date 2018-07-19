'use strict';

var envvar = require('envvar');
var express = require('express');
var bodyParser = require('body-parser');
var moment = require('moment');
var plaid = require('plaid');
var crypto = require('crypto');
var AWS = require('aws-sdk');
var uuid = require('uuid/v4');
var buffer = require('buffer');

var APP_PORT = envvar.number('APP_PORT', 8000);
var PLAID_CLIENT_ID = envvar.string('PLAID_CLIENT_ID');
var PLAID_SECRET = envvar.string('PLAID_SECRET');
var PLAID_PUBLIC_KEY = envvar.string('PLAID_PUBLIC_KEY');
var PLAID_ENV = envvar.string('PLAID_ENV', 'sandbox');
AWS.config.loadFromPath("./awsconfig.json");

// We store the access_token in memory - in production, store it in a secure
// persistent data store
var ACCESS_TOKEN = null;
var PUBLIC_TOKEN = null;
var ITEM_ID = null;

// Initialize the Plaid client
var client = new plaid.Client(
  PLAID_CLIENT_ID,
  PLAID_SECRET,
  PLAID_PUBLIC_KEY,
  plaid.environments[PLAID_ENV]
);

var app = express();
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(bodyParser.json());

app.get('/', function(request, response, next) {
  response.render('index.ejs', {
    PLAID_PUBLIC_KEY: PLAID_PUBLIC_KEY,
    PLAID_ENV: PLAID_ENV,
  });
});

app.post('/get_access_token', function(request, response, next) {

  PUBLIC_TOKEN = request.body.public_token;
//  PUBLIC_TOKEN = "public-sandbox-6a64e098-1d87-42ae-856e-5d9077a61b8b";
  client.exchangePublicToken(PUBLIC_TOKEN, function(error, tokenResponse) {
    if (error != null) {
      var msg = 'Could not exchange public_token!';
      console.log(msg + '\n' + JSON.stringify(error));
      return response.json({
        error: msg
      });
    }
    ACCESS_TOKEN = tokenResponse.access_token;
    ITEM_ID = tokenResponse.item_id;
    console.log('Access Token: ' + ACCESS_TOKEN);
    console.log('Item ID: ' + ITEM_ID);
    response.json({
      'error': false
    });
  });
});

app.get('/accounts', function(request, response, next) {

  // Retrieve high-level account information and account and routing numbers
  // for each account associated with the Item.
  client.getAuth(ACCESS_TOKEN, function(error, authResponse) {
    if (error != null) {
      var msg = 'Unable to pull accounts from the Plaid API.';
      console.log(msg + '\n' + JSON.stringify(error));
      return response.json({
        error: msg
      });
    }

    console.log(authResponse.accounts);
    response.json({
      error: false,
      accounts: authResponse.accounts,
      numbers: authResponse.numbers,
    });
  });
});

app.post('/item', function(request, response, next) {
  // Pull the Item - this includes information about available products,
  // billed products, webhook information, and more.
  client.getItem(ACCESS_TOKEN, function(error, itemResponse) {
    if (error != null) {
      console.log(JSON.stringify(error));
      return response.json({
        error: error
      });
    }

    // Also pull information about the institution
    client.getInstitutionById(itemResponse.item.institution_id, function(err, instRes) {
      if (err != null) {
        var msg = 'Unable to pull institution information from the Plaid API.';
        console.log(msg + '\n' + JSON.stringify(error));
        return response.json({
          error: msg
        });
      } else {
        response.json({
          item: itemResponse.item,
          institution: instRes.institution,
        });
      }
    });
  });
});

function createTxRecord(txn) {
    var record = {tx_id:"", tx_details:{}};

    record.tx_details.merchant_name = txn.name;
    record.tx_details.amount = txn.amount;
    record.tx_details.date = txn.date;
    record.tx_details.account_id = txn.account_id;
    record.tx_details.account_owner = txn.account_owner;
    record.tx_details.category_id = txn.category_id;
    record.tx_details.category_0 = txn.category[0];
    record.tx_details.category_1 = txn.category[1];
    record.tx_details.address = txn.location.address;
    record.tx_details.city = txn.location.city;
    record.tx_details.lat = txn.location.lat;
    record.tx_details.lon = txn.location.lon;
    record.tx_details.state = txn.location.state;
    record.tx_details.store_number = txn.location.store_number;
    record.tx_details.zip = txn.location.zip;

    record.tx_details.payment_by_order_of = txn.payment_meta.by_order_of;
    record.tx_details.payee = txn.payment_meta.payee;
    record.tx_details.payer = txn.payment_meta.payer;
    record.tx_details.payment_method = txn.payment_meta.payment_method;
    record.tx_details.payment_processor = txn.payment_meta.payment_processor;
    record.tx_details.ppd_id = txn.payment_meta.ppd_id;
    record.tx_details.reason = txn.payment_meta.reason;
    record.tx_details.reference_number = txn.payment_meta.reference_number;

    record.tx_details.pending = txn.pending;
    record.tx_details.pending_tx_id = txn.pending_transaction_id;
    record.tx_details.tx_type = txn.transaction_type;
    record.tx_details.tx_id = txn.transaction_id;

    record.tx_id = txn.transaction_id;

    return record;
}

function exportToS3(transactions, accountId, encryptionKey) {
  var storage_handle = "";
  if(!accountId) {
        storage_handle = 'desilo-'+ uuid();
        var bucket_result = createS3Bucket(storage_handle);
        if(!bucket_result.success) {
          return {success:false, errors: [bucket_result.error],
              total: transactions.size, account_id:"", encryption_key:""}
        }
    } else {
    storage_handle = accountId;
  }
    var encryption_key = "";
    if(!encryptionKey) {
        encryption_key = new Buffer(crypto.randomBytes(32), 'utf8');
    } else {
      encryption_key = Buffer.from(encryptionKey, "base64");
    }

    var result = {success:false, errors: [], total: transactions.size, account_id:storage_handle,
        encryption_key:encryption_key.toString("base64")};
  transactions.forEach(function (txn, idx) {
    var record = createTxRecord(txn);
    var record_result = addRecord(record, storage_handle, encryption_key);
    if(!record_result.success) {
      result.success = false;
      result.errors.push(record_result.error);
    }
    result.success = true;
  });

  return result;
}

app.post('/tos3', function (request, response, next) {
    var start = parseInt(request.body.start);
    var accountId = request.body.storage_id;
    var encryptionKey = request.body.encryption_key;
    var startDate = moment().subtract(30, 'days').format('YYYY-MM-DD');
    if(start > 0) {
      startDate = moment().subtract(30 * start, 'days').format('YYYY-MM-DD');
    }
    var endDate = moment().format('YYYY-MM-DD');

    client.getTransactions(ACCESS_TOKEN, startDate, endDate, {count:250, offset:0,},
        function (err, txResp) {
            if (err != null) {
              console.log(JSON.stringify(err));
              return response.json({error: err});
            }
            console.log('pulled ' + txResp.transactions.length + ' transactions');
            var result = exportToS3(txResp.transactions, accountId, encryptionKey);
            response.json(result);
        }
    );

});

app.post('/transactions', function(request, response, next) {
  // Pull transactions for the Item for the last 30 days

    var startDate = moment().subtract(30, 'days').format('YYYY-MM-DD');

  var endDate = moment().format('YYYY-MM-DD');
  client.getTransactions(ACCESS_TOKEN, startDate, endDate, {
    count: 250,
    offset: 0,
  }, function(error, transactionsResponse) {
    if (error != null) {
      console.log(JSON.stringify(error));
      return response.json({
        error: error
      });
    }
    console.log('pulled ' + transactionsResponse.transactions.length + ' transactions');
    response.json(transactionsResponse);
  });
});

function createS3Bucket(bucketName) {
    var s3 = new AWS.S3();
    var bucketParams = {
        Bucket : bucketName,
        ACL : 'private'
    };
    var result = {};
    s3.createBucket(bucketParams, function (err, data) {
      if(err){
        console.log("Create Bucket Error", err);
        result.success = false;
        result.error = err;
      } else {
        console.log("Create Bucket Success");
        result.success = true;
      }
    });
    return result;
}

function encryptRecord(record, encryption_key) {
    const iv = new Buffer(record.tx_id, 'utf8');
    const cipher = crypto.createCipheriv('aes-256-gcm', encryption_key, iv);
    var enc = cipher.update(JSON.stringify(record), 'utf8', 'base64');
    enc += cipher.final('base64');

    return {enc_record:enc, auth_tag:cipher.getAuthTag().toString('base64')};
}

function addRecord(record, storage_handle, encryption_key) {
    var s3 = new AWS.S3();
    var encryptedRecord = encryptRecord(record, encryption_key);
    var uploadParams = {Bucket: storage_handle, Key: record.tx_id, Body: JSON.stringify(encryptedRecord)};

    var result = {success: true, error: null};
    s3.upload(uploadParams, function (err, data) {
       if(err){
         console.log("Error" + record.tx_id);
         result = {success: false, error: err};
       } else {
         console.log("Success" + record.tx_id);
         result = {success: true, error: null};
       }
    });
    return result;
}

var server = app.listen(APP_PORT, function() {
  // createS3Bucket('desilo-test-sivag')
  console.log('plaid-walkthrough server listening on port ' + APP_PORT);
});
