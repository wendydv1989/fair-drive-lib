const chai = require('chai')
const spies = require('chai-spies')
const util = require('util')
const fs = require('fs')
var path = require('path');

const Fairdrive = require('../src/fairdrive-lib')
const appicon = "data:image/jpeg;base64,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"
const appname = "tODOlIST"

const swarm = require('swarm-lowlevel')
const wallet = new swarm.unsafeWallet()

var mmm = require('mmmagic'),
    Magic = mmm.Magic;

var magic = new Magic(mmm.MAGIC_MIME_TYPE);

const readFileAsync = util.promisify(fs.readFile)

let hash = ""

chai.use(spies)
const expect = chai.expect

const fd = new Fairdrive('http://localhost:8080/chunks')

let mnemonic = ""
let fairdrivewallet = {}
let keyPairNonce = ""
let myFairdrive = {}
console.log()

describe('Fairdrive', () => {
    describe('Testing', () => {
        it('can set a feed', async () => {
            const res = await fd.setFeed("topic", { username: "michelle" }, wallet.privateKey)
            hash = res
        })
        it('can get a feed', async () => {

            const res = await fd.getFeed("topic", wallet.privateKey)
        })
        it('creates a new fairdrive', async () => {
            const fairdrive = await fd.newFairdrive()
            fairdrivewallet = fairdrive.wallet
            mnemonic = fairdrive.mnemonic
            keyPairNonce = fairdrive.keyPairNonce
        })
        it('retrieves the new fairdrive', async () => {
            const fairdrive = await fd.getFairdrive(mnemonic)
            myFairdrive = fairdrive
            console.log(fairdrive)
        })
        it('retrieves folder', async () => {
            // find documents folder
            const getKey = async (name) => {
                for (const [key, value] of Object.entries(myFairdrive.content)) {
                    const searchTerm = name
                    if (value.name === searchTerm)
                        return { key: value.id, keyIndex: value.keyIndex }
                }
            }
            const folder = await getKey('Movies')
            const path = folder.key
            const keyIndex = folder.keyIndex
            const resFolder = await fd.getFolder(path, keyIndex, mnemonic)
            console.log(resFolder)
        })
        it('uploads a file to fairdrive root', async () => {
            let filePath = 'test/helloworld.txt'
            var fileName = filePath.replace(/^.*[\\\/]/, '')
            let mime = ""
            magic.detectFile('test/helloworld.txt', function (err, result) {
                if (err) throw err;
                console.log('what file: ', result);
                mime = result
                // output on Windows with 32-bit node:
                //    PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
            });

            fileData = await readFileAsync('test/helloworld.txt')
            const file = {
                data: fileData,
                mime: mime,
                name: fileName,
                thumb: "text"
            }
            const fairdrive = await fd.newFile(file, undefined, mnemonic, 0)
            myFairdrive = fairdrive
            console.log(fairdrive)
        })



        // it(appname + ' creates a request to connect', async () => {
        //     const res = await fd.createConnect(appname, appicon).then(res => {
        //         console.log(res)
        //     })
        // })
    })
})