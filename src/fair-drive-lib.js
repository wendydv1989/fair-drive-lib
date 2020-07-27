const { createKeyPair } = require('@erebos/secp256k1')
const { pubKeyToAddress } = require('@erebos/keccak256')
const EthCrypto = require("eth-crypto")
const ethers = require("ethers")
const { BeeClient } = require("bee-client")
const textEncoding = require('text-encoding')
const swarm = require('swarm-lowlevel')

const td = new textEncoding.TextDecoder("utf-8")
const te = new textEncoding.TextEncoder("utf-8")

const { toHex, hexToByteArray, byteArrayToHex, numbersToByteArray, stringToUint8Array } = require('./conversion')

//const fds = new FDS()

function Fairdrive() { }

// Fairdrive.prototype.getFeed = async function (address, topic) {
//     const res = await fds.Account.SwarmStore.SF.get(address, topic)
//     return JSON.parse(res)
// }

Fairdrive.prototype.setFeed = async function (topic, data, privateKey) {
    const bee = new BeeClient("http://localhost:8080/chunks", null)
    const wallet = new swarm.unsafeWallet(Buffer.from(privateKey))
    const rawTopic = te.encode(topic);
    const uint8 = new Uint8Array(32);
    uint8.set(rawTopic, 0)
    const cleanTopic = uint8
    const cleanData = te.encode(JSON.stringify(data))
    const feed = await bee.updateFeedWithTopic(
        cleanTopic,
        cleanData,
        wallet)
    return feed
}

// Fairdrive.prototype.newFairdrive = async function () {
//     let bytes = ethers.utils.randomBytes(16);
//     let language = ethers.wordlists.en;
//     let randomMnemonic = await ethers.utils.entropyToMnemonic(bytes, language)
//     let mnemonic = randomMnemonic
//     let wallet = await ethers.utils.HDNode.fromMnemonic(randomMnemonic)
//     const documentsFolder = await this.newFolder("Documents", mnemonic, 0)
//     const picturesFolder = await this.newFolder("Pictures", mnemonic, 1)
//     const moviesFolder = await this.newFolder("Movies", mnemonic, 0)
//     const moviesFolder = await this.newFolder("Movies", mnemonic, 0)
//     const moviesFolder = await this.newFolder("Movies", mnemonic, 0)

//     const tempFolderId = new Date().toISOString()
//     const tempFolderFeed = await fds.Account.SwarmStore.SF.set(
//         wallet1.address,
//         'fairdrive-temp',
//         wallet1.privateKey,
//         {
//             keyIndex: 1,
//             name: "Temporary",
//             ownerAddress: wallet1.address,
//             content: {}
//         })
//     const dappFolderFeed = await fds.Account.SwarmStore.SF.set(
//         wallet2.address,
//         'fairdrive-dappdata',
//         wallet2.privateKey,
//         {
//             keyIndex: 2,
//             name: "DappData",
//             ownerAddress: wallet2.address,
//             content: {}
//         })
//     const hash2 = await fds.Account.SwarmStore.SF.set(
//         wallet.address,
//         'fairdrive',
//         wallet.privateKey,
//         {
//             "Temporary": {
//                 name: 'Temporary',
//                 address: wallet1.address
//             },
//             "DappData": {
//                 name: 'DappData',
//                 address: wallet2.address
//             }
//         })
//     return { mnemonic, wallet }
// }

// Fairdrive.prototype.createConnect = async function (appname, appicon) {
//     const PRIVATE_KEY_BYTES_LENGTH = 32
//     const PUBLIC_KEY_BYTES_LENGTH = 33
//     const ADDRESS_BYTES_LENGTH = 20
//     var timeStamp = Math.round((new Date()).getTime() / 100000);
//     const shortCode = Math.floor(1000 + Math.random() * 9000);
//     const seedstring = shortCode.toString().concat('-fairdrive-', timeStamp.toString())
//     const privateKeyGenerated = byteArrayToHex(stringToUint8Array(seedstring), false)
//     const keyPair = createKeyPair(privateKeyGenerated)
//     const keyPair_toSign = createKeyPair()
//     const privateKey = toHex(hexToByteArray(keyPair.getPrivate('hex'), PRIVATE_KEY_BYTES_LENGTH))
//     const publicKey = toHex(hexToByteArray(keyPair_toSign.getPublic(true, 'hex'), PUBLIC_KEY_BYTES_LENGTH))

//     const address = pubKeyToAddress(keyPair.getPublic('array'))
//     const swarmFeed = await this.setFeed(
//         address,
//         'shortcode',
//         privateKey,
//         {
//             appname: appname,
//             appicon: appicon,
//             publicKey: publicKey
//         })

//     return {
//         shortCode: shortCode, 
//         gotUrl: 'https://fairdrive.io/#/connect/shortCode'
//     }
// }

// Fairdrive.prototype.authenticateApp = async function (folderName, mnemonic, address, keyPairNonce, givenPrivateKey, username, avatar) {

//     const res = await this.newFolder(folderName, mnemonic, keyPairNonce, username, avatar)

//     const newSwarmFeed = await this.setFeed(
//         address,
//         'shortcode',
//         givenPrivateKey,
//         {
//             status: 200,
//             encryptedReturnObject: res
//         })

//     return true
// }
// Fairdrive.prototype.resolveConnect = async function (id, givenPrivateKey) {
//     if (!givenPrivateKey) throw 'no private key!'
//     if (!id) throw 'no shortcode!'
//     var timeStamp = Math.round((new Date()).getTime() / 100000);
//     const shortCode = id
//     const seedstring = shortCode.toString().concat('-fairdrive-', timeStamp.toString())
//     const privateKeyGenerated = byteArrayToHex(stringToUint8Array(seedstring), false)
//     const keyPair = createKeyPair(privateKeyGenerated)
//     const privateKey = toHex(hexToByteArray(keyPair.getPrivate('hex'), PRIVATE_KEY_BYTES_LENGTH))
//     const publicKey = toHex(hexToByteArray(keyPair.getPublic(true, 'hex'), PUBLIC_KEY_BYTES_LENGTH))
//     const address = pubKeyToAddress(keyPair.getPublic('array'))
//     const result = await this.getFeed(address, 'shortcode')

//     return result
// }

// Fairdrive.prototype.newFolder = async function (folderName, mnemonic, keyPairNonce) {
//     let wallet = await ethers.utils.HDNode.fromMnemonic(mnemonic)
//     const folderWallet = wallet.derivePath(`"m/44'/60'/'/0/` + keyPairNonce + `"`)
//     const newNonce = keyPairNonce++
//     const newId = new Date().toISOString()
//     const newFolderFeed = await this.setFeed(
//         folderWallet.address,
//         folderName,
//         folderWallet.privateKey,
//         {
//             id: newId,
//             keyIndex: newNonce,
//             name: folderName,
//             ownerAddress: folderWallet.address,
//             content: {}
//         })

//     return {id: newId, feed: newFolderFeed, address: folderWallet.address, nonce: newNonce }
// }


module.exports = Fairdrive