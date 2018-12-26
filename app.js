/*
9cf492dcd4a1724470181fcfeff833710eec58fd6a4e926a8b760266dfde9659
TsX1TGWi6Ss6CPNz7kcGSq5be7Q1ogVyerK
*/

const bitcore = require('bitcore-lib')
var explorers = require('bitcore-explorers');
var insight = new explorers.Insight('https://testnet.decred.org'); // https://mainnet.decred.org/

// // generate pub/priv key
const network = bitcore.Networks.dcrtestnet // dcrdlivenet
const privateKey = new bitcore.PrivateKey('9cf492dcd4a1724470181fcfeff833710eec58fd6a4e926a8b760266dfde9659', network);
const publicKey = bitcore.PublicKey(privateKey);
const address = publicKey.toAddress(network)
console.log({privateKey, publicKey, address})

insight.getUnspentUtxos('TsX1TGWi6Ss6CPNz7kcGSq5be7Q1ogVyerK', function(err, utxos) {
  // https://github.com/bitpay/bitcore-lib/blob/master/docs/examples.md#create-a-transaction
  const tx = new bitcore.Transaction(network)
    .from(utxos)
    .to(address, 5 * 100000000) // send 5 DCR
    .change(address)
    .sign(privateKey)
    // https://testnet.decred.org/tx/send
    console.log(tx)
})



