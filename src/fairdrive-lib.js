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

function Fairdrive(beeGateway) {
    this.beeGateway = beeGateway || "http://localhost:8080/chunks"
    const bee = new BeeClient(this.beeGateway, null)
    this.bee = bee
}

Fairdrive.prototype.getFeed = async function (topic, privateKey) {
    const wallet = new swarm.unsafeWallet(Buffer.from(privateKey))
    const rawTopic = te.encode(topic);
    const uint8 = new Uint8Array(32);
    uint8.set(rawTopic, 0)
    const cleanTopic = uint8
    const rawRes = await this.bee.getFeedWithSalt(cleanTopic, wallet)
    const res = td.decode(rawRes.chunk.data)
    return res
}

Fairdrive.prototype.setFeed = async function (topic, data, privateKey) {
    const wallet = new swarm.unsafeWallet(Buffer.from(privateKey))
    const rawTopic = te.encode(topic);
    const uint8 = new Uint8Array(32);
    uint8.set(rawTopic, 0)
    const cleanTopic = uint8
    const cleanData = te.encode(JSON.stringify(data))
    const feed = await this.bee.updateFeedWithSalt(
        cleanTopic,
        cleanData,
        wallet)
    return feed
}

Fairdrive.prototype.newFairdrive = async function () {
    let bytes = ethers.utils.randomBytes(16);
    let language = ethers.wordlists.en;
    let randomMnemonic = await ethers.utils.entropyToMnemonic(bytes, language)
    let mnemonic = randomMnemonic
    let wallet = await ethers.utils.HDNode.fromMnemonic(randomMnemonic)

    const baseDrive = await this.setFeed(
        'fairdrive',
        {
            keyIndex: 0,
            lastUpdated: new Date().toISOString(),
            type: 'root',
            content: {
            }
        },
        hexToByteArray(wallet.privateKey)
    )

    const documentsFolder = await this.newFolder("Documents", undefined, mnemonic)
    const picturesFolder = await this.newFolder("Pictures", undefined, mnemonic)
    const moviesFolder = await this.newFolder("Movies", undefined, mnemonic)
    const dappconnectFolder = await this.newFolder("DappConnect", undefined, mnemonic)
    const todoListAppFolder = await this.newFolder("ToDOListDapp", dappconnectFolder, mnemonic)

    return { mnemonic, wallet }
}

Fairdrive.prototype.getFairdrive = async function (mnemonic) {
    let wallet = ethers.utils.HDNode.fromMnemonic(mnemonic)
    let privateKey = hexToByteArray(wallet.privateKey)
    let fairdrive = await this.getFeed("fairdrive", privateKey)
    return JSON.parse(fairdrive)
}

Fairdrive.prototype.newFolder = async function (folderName, path, mnemonic) {
    let wallet = await ethers.utils.HDNode.fromMnemonic(mnemonic)
    const fairdrive = await this.getFairdrive(mnemonic)
    console.debug(fairdrive)
    const newNonce = fairdrive.keyIndex + 1
    const folderWallet = wallet.derivePath("m/44'/60'/0'/0/" + newNonce)
    const newId = new Date().toISOString()
    const newFolderFeed = await this.setFeed(
        newId,
        {
            id: newId,
            keyIndex: newNonce,
            lastUpdated: new Date().toISOString(),
            type: 'folder',
            name: folderName,
            ownerAddress: folderWallet.address,
            nonce: 0,
            content: {}
        },
        hexToByteArray(folderWallet.privateKey)
    )

    if (path) {
        console.debug('setwithPath: ', path, fairdrive.content[path])
        debugger
        fairdrive.content[path].content[newId] = {
            id: newId,
            keyIndex: newNonce,
            lastUpdated: new Date().toISOString(),
            type: 'folder',
            name: folderName,
            lastUpdated: new Date().toISOString(),
            address: folderWallet.address,
            content: {}
        }
    } else {
        fairdrive.content[newId] = {
            id: newId,
            keyIndex: newNonce,
            lastUpdated: new Date().toISOString(),
            type: 'folder',
            name: folderName,
            lastUpdated: new Date().toISOString(),
            address: folderWallet.address,
            content: {}
        }
    }

    fairdrive.keyIndex = newNonce

    const updateFairdrive = await this.setFeed(
        'fairdrive',
        fairdrive,
        hexToByteArray(wallet.privateKey)
    )

    return newId
}

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

//     const res = await this.newConnectFolder(folderName, mnemonic, keyPairNonce, username, avatar)

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

module.exports = Fairdrive