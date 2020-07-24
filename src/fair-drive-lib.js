const { createKeyPair } = require('@erebos/secp256k1')
const { pubKeyToAddress } = require ('@erebos/keccak256')
const EthCrypto = require ("eth-crypto")
const ethers = require ("ethers")
const FDS = require ("fds.js")

const { toHex, hexToByteArray, byteArrayToHex, numbersToByteArray, stringToUint8Array } = require('./conversion')

//const fds = new FDS()
const fds = new FDS({
    tokenName: 'gas',
    swarmGateway: 'https://swarm2.fairdatasociety.org',
    ethGateway: 'https://geth-noordung.fairdatasociety.org',
    faucetAddress: 'https://faucet-noordung.fairdatasociety.org/gimmie',
    chainID: '235813',
    httpTimeout: 1000,
    gasPrice: 0.1,
    walletVersion: 1,
    scratchDir: './scratch',
    ensConfig: {
        domain: 'datafund.eth',
        registryAddress: '0xA1029cb176082eca658A67fD6807B9bDfB44A695',
        subdomainRegistrarAddress: '0x0E6a3B5f6800145bAe95C48934B7b5a90Df50722',
        resolverContractAddress: '0xC91AB84FFad79279D47a715eF91F5fbE86302E4D'
    }
})

function Fairdrive() {}

Fairdrive.prototype.getFeed = async function (address, topic) {
    const res = await fds.Account.SwarmStore.SF.get(address, topic)
    return JSON.parse(res)
}

Fairdrive.prototype.setFeed = async function (address, topic, privateKey, data) {
    const feed = await fds.Account.SwarmStore.SF.set(
        address,
        topic,
        privateKey,
        data)
    return feed
}

Fairdrive.prototype.createConnect = async function (appname, appicon) {
    const PRIVATE_KEY_BYTES_LENGTH = 32
    const PUBLIC_KEY_BYTES_LENGTH = 33
    const ADDRESS_BYTES_LENGTH = 20
    var timeStamp = Math.round((new Date()).getTime() / 100000);
    const shortCode = Math.floor(1000 + Math.random() * 9000);
    const seedstring = shortCode.toString().concat('-fairdrive-', timeStamp.toString())
    const privateKeyGenerated = byteArrayToHex(stringToUint8Array(seedstring), false)
    const keyPair = createKeyPair(privateKeyGenerated)
    const keyPair_toSign = createKeyPair()
    const privateKey = toHex(hexToByteArray(keyPair.getPrivate('hex'), PRIVATE_KEY_BYTES_LENGTH))
    const publicKey = toHex(hexToByteArray(keyPair_toSign.getPublic(true, 'hex'), PUBLIC_KEY_BYTES_LENGTH))

    const address = pubKeyToAddress(keyPair.getPublic('array'))
    const swarmFeed = await this.setFeed(
        address,
        'shortcode',
        privateKey,
        {
            appname: appname,
            appicon: appicon,
            publicKey: publicKey
        })

    return {
        shortCode: shortCode, 
        gotUrl: 'https://fairdrive.io/#/connect/shortCode'
    }
}

Fairdrive.prototype.authenticateApp = async function (folderName, mnemonic, address, keyPairNonce, givenPrivateKey, username, avatar) {

    const res = await this.newFolder(folderName, mnemonic, keyPairNonce, username, avatar)

    const newSwarmFeed = await this.setFeed(
        address,
        'shortcode',
        givenPrivateKey,
        {
            status: 200,
            encryptedReturnObject: res
        })

    return true
}
Fairdrive.prototype.resolveConnect = async function (id, givenPrivateKey) {
    if (!givenPrivateKey) throw 'no private key!'
    if (!id) throw 'no shortcode!'
    var timeStamp = Math.round((new Date()).getTime() / 100000);
    const shortCode = id
    const seedstring = shortCode.toString().concat('-fairdrive-', timeStamp.toString())
    const privateKeyGenerated = byteArrayToHex(stringToUint8Array(seedstring), false)
    const keyPair = createKeyPair(privateKeyGenerated)
    const privateKey = toHex(hexToByteArray(keyPair.getPrivate('hex'), PRIVATE_KEY_BYTES_LENGTH))
    const publicKey = toHex(hexToByteArray(keyPair.getPublic(true, 'hex'), PUBLIC_KEY_BYTES_LENGTH))
    const address = pubKeyToAddress(keyPair.getPublic('array'))
    const result = await this.getFeed(address, 'shortcode')

    return result
}

Fairdrive.prototype.newFolder = async function (folderName, mnemonic, keyPairNonce, givenPublicKey, username, avatar) {
    let wallet = await ethers.utils.HDNode.fromMnemonic(mnemonic)
    const folderWallet = wallet.derivePath("m/44'/60'/" + keyPairNonce + "'/0/0")
    const newNonce = keyPairNonce + 1
    const newFolderFeed = await this.setFeed(
        folderWallet.address,
        folderName,
        folderWallet.privateKey,
        {
            keyIndex: newNonce,
            name: folderName,
            ownerAddress: folderWallet.address,
            content: {}
        })

    const prevFairdrive = await this.getFeed(wallet.address, 'fairdrive')

    const folderId = new Date().toISOString()

    prevFairdrive[folderId] = {
        name: folderName,
        address: folderWallet.address
    }

    const hash2 = await this.setFeed(
        wallet.address,
        'fairdrive',
        wallet.privateKey,
        prevFairdrive)

    const PUBLIC_KEY_BYTES_LENGTH = 33

    const returnObject = { pk: folderWallet.privateKey, username: username, avatar: avatar }

    const publicKeyArray = hexToByteArray(givenPublicKey, PUBLIC_KEY_BYTES_LENGTH)
    const encrypted = await EthCrypto.encryptWithPublicKey(
        publicKeyArray, // publicKey
        JSON.stringify(returnObject) // message
    );

    return encrypted
}


module.exports = Fairdrive