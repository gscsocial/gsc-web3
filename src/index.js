import providers from 'library/request';
import tools from 'tools';
import BigNumber from 'bignumber.js';
import EventEmitter from 'eventemitter3';
import { version } from '../package.json';
import semver from 'semver';

import TransactionBuilder from 'library/trxBuilder';
import Gsc from 'library/gsc';
import Contract from 'library/smartContract';
import Plugin from 'library/plugin';
import Event from 'library/event';
import { keccak256 } from 'tools/ethersUtils';
import { ADDRESS_PREFIX } from 'tools/address';

const DEFAULT_VERSION = '3.5.0';

export default class GSCWeb3 extends EventEmitter {
    static providers = providers;
    static BigNumber = BigNumber;
    static TransactionBuilder = TransactionBuilder;
    static Gsc = Gsc;
    static Contract = Contract;
    static Plugin = Plugin;
    static Event = Event;
    static version = version;
    static tools = tools;

    constructor(options = false,
        confirmedNode = false, eventServer = false, privateKey = false) {
        super();

        let fullNode;
        if (typeof options === 'object' && (options.fullNode || options.fullHost)) {
            fullNode = options.fullNode || options.fullHost;
            confirmedNode = options.confirmedNode || options.fullHost;
            eventServer = options.eventServer || options.fullHost;
            privateKey = options.privateKey;
        } else {
            fullNode = options;
        }

        if (tools.isString(fullNode))
            fullNode = new providers.getRequest(fullNode);

        if (tools.isString(confirmedNode))
            confirmedNode = new providers.getRequest(confirmedNode);

        if (tools.isString(eventServer))
            eventServer = new providers.getRequest(eventServer);

        this.event = new Event(this);
        this.transactionBuilder = new TransactionBuilder(this);
        this.gsc = new Gsc(this);
        this.plugin = new Plugin(this);
        this.tools = tools;

        this.setFullNode(fullNode);
        this.setConfirmedNode(confirmedNode);
        this.setEventServer(eventServer);

        this.providers = providers;
        this.BigNumber = BigNumber;

        this.defaultBlock = false;
        this.defaultPrivateKey = false;
        this.defaultAddress = {
            hex: false,
            base58: false
        };

        [
            'sha3', 'toHex', 'toUtf8', 'fromUtf8',
            'toAscii', 'fromAscii', 'toDecimal', 'fromDecimal',
            'toDOT', 'fromDOT', 'toBigNumber', 'isAddress',
            'createAccount', 'address', 'version'
        ].forEach(key => {
            this[key] = GSCWeb3[key];
        });

        if (privateKey)
            this.setPrivateKey(privateKey);

        this.fullnodeVersion = DEFAULT_VERSION;
        this.injectPromise = tools.promiseInjector(this);
    }

    async getFullnodeVersion() {
        try {
            const nodeInfo = await this.gsc.getNodeInfo()
            this.fullnodeVersion = nodeInfo.configNodeInfo.codeVersion
            if (this.fullnodeVersion.split('.').length === 2) {
                this.fullnodeVersion += '.0';
            }
        } catch (err) {
            this.fullnodeVersion = DEFAULT_VERSION;
        }
    }

    setDefaultBlock(blockID = false) {
        if ([false, 'latest', 'earliest', 0].includes(blockID)) {
            return this.defaultBlock = blockID;
        }

        if (!tools.isInteger(blockID) || !blockID)
            throw new Error('Error: code id: 10000');

        this.defaultBlock = Math.abs(blockID);
    }

    setPrivateKey(privateKey) {
        try {
            this.setAddress(
                this.address.fromPrivateKey(privateKey)
            );
        } catch {
            throw new Error('Error: code id: 10001');
        }

        this.defaultPrivateKey = privateKey;
        this.emit('privateKeyChanged', privateKey);
    }

    setAddress(address) {
        if (!this.isAddress(address))
            throw new Error('Error: code id: 10002');

        const hex = this.address.toHex(address);
        const base58 = this.address.fromHex(address);

        if (this.defaultPrivateKey && this.address.fromPrivateKey(this.defaultPrivateKey) !== base58)
            this.defaultPrivateKey = false;

        this.defaultAddress = {
            hex,
            base58
        };

        this.emit('addressChanged', { hex, base58 });
    }

    fullnodeSatisfies(version) {
        return semver.satisfies(this.fullnodeVersion, version);
    }

    isValidProvider(provider) {
        return Object.values(providers).some(knownProvider => provider instanceof knownProvider);
    }

    setFullNode(fullNode) {
        if (tools.isString(fullNode))
            fullNode = new providers.getRequest(fullNode);

        if (!this.isValidProvider(fullNode))
            throw new Error('Error: code id: 10003');

        this.fullNode = fullNode;
        this.fullNode.setStatusPage('wallet/getnowblock');

        this.getFullnodeVersion();
    }

    setConfirmedNode(confirmedNode) {
        if (tools.isString(confirmedNode))
            confirmedNode = new providers.getRequest(confirmedNode);

        if (!this.isValidProvider(confirmedNode))
            throw new Error('Error: code id: 10004');

        this.confirmedNode = confirmedNode;
        this.confirmedNode.setStatusPage('walletconfirmed/getnowblock');
    }

    setEventServer(...params) {
        this.event.setServer(...params)
    }

    currentProviders() {
        return {
            fullNode: this.fullNode,
            confirmedNode: this.confirmedNode,
            eventServer: this.eventServer
        };
    }

    currentProvider() {
        return this.currentProviders();
    }


    getEventResult(...params) {

        if (typeof params[1] !== 'object') {
            params[1] = {
                sinceTimestamp: params[1] || 0,
                eventName: params[2] || false,
                blockNumber: params[3] || false,
                size: params[4] || 20,
                page: params[5] || 1
            }
            params.splice(2, 4)
            if (!tools.isFunction(params[2])) {
                if (tools.isFunction(params[1].page)) {
                    params[2] = params[1].page;
                    params[1].page = 1;
                } else if (tools.isFunction(params[1].size)) {
                    params[2] = params[1].size;
                    params[1].size = 20;
                    params[1].page = 1;
                }
            }
        }

        return this.event.getEventsByContractAddress(...params);
    }

    getEventByTransactionID(...params) {
        return this.event.getEventsByTransactionID(...params)
    }

    contract(abi = [], address = false) {
        return new Contract(this, abi, address);
    }

    static get address() {
        return {
            fromHex(address) {
                if (!tools.isHex(address))
                    return address;
                return tools.crypto.getBase58CheckAddress(
                    tools.code.hexStr2byteArray(address.replace(/^0x/, ADDRESS_PREFIX))
                );
            },
            toHex(address) {
                if (tools.isHex(address))
                    return address.toLowerCase().replace(/^0x/, ADDRESS_PREFIX);
                return tools.code.byteArray2hexStr(
                    tools.crypto.decodeBase58Address(address)
                ).toLowerCase();
            },
            fromPrivateKey(privateKey) {
                try {
                    return tools.crypto.pkToAddress(privateKey);
                } catch {
                    return false;
                }
            }
        }
    }

    static sha3(string, prefix = true) {
        return (prefix ? '0x' : '') + keccak256(Buffer.from(string, 'utf-8')).toString().substring(2);
    }

    static toHex(val) {
        if (tools.isBoolean(val))
            return GSCWeb3.fromDecimal(+val);
        if (tools.isBigNumber(val))
            return GSCWeb3.fromDecimal(val);

        if (typeof val === 'object')
            return GSCWeb3.fromUtf8(JSON.stringify(val));

        if (tools.isString(val)) {
            if (/^(-|)0x/.test(val))
                return val;

            if (!isFinite(val))
                return GSCWeb3.fromUtf8(val);
        }

        let result = GSCWeb3.fromDecimal(val);
        if (result === '0xNaN') {
            throw new Error('Error: code id: 10005');
        } else {
            return result;
        }
    }

    static toUtf8(hex) {
        if (tools.isHex(hex)) {
            hex = hex.replace(/^0x/, '');
            return Buffer.from(hex, 'hex').toString('utf8');
        } else {
            throw new Error('Error: code id: 10006');
        }
    }

    static fromUtf8(string) {
        if (!tools.isString(string)) {
            throw new Error('Error: code id: 10007')
        }
        return '0x' + Buffer.from(string, 'utf8').toString('hex');
    }

    static toAscii(hex) {
        if (tools.isHex(hex)) {
            let str = "";
            let i = 0, l = hex.length;
            if (hex.substring(0, 2) === '0x') {
                i = 2;
            }
            for (; i < l; i += 2) {
                let code = parseInt(hex.substr(i, 2), 16);
                str += String.fromCharCode(code);
            }
            return str;
        } else {
            throw new Error('Error: code id: 10006');
        }
    }

    static fromAscii(string, padding) {
        if (!tools.isString(string)) {
            throw new Error('Error: code id: 10007')
        }
        return '0x' + Buffer.from(string, 'ascii').toString('hex').padEnd(padding, '0');
    }


    static toDecimal(value) {
        return GSCWeb3.toBigNumber(value).toNumber();
    }

    static fromDecimal(value) {
        const number = GSCWeb3.toBigNumber(value);
        const result = number.toString(16);
        return number.isLessThan(0) ? '-0x' + result.substr(1) : '0x' + result;
    }

    static fromDOT(sun) {
        const gsc = GSCWeb3.toBigNumber(sun).div(1_000_000);
        return tools.isBigNumber(sun) ? gsc : gsc.toString(10);
    }

    static toDOT(gsc) {
        const sun = GSCWeb3.toBigNumber(gsc).times(1_000_000);
        return tools.isBigNumber(gsc) ? sun : sun.toString(10);
    }

    static toBigNumber(amount = 0) {
        if (tools.isBigNumber(amount))
            return amount;

        if (tools.isString(amount) && /^(-|)0x/.test(amount))
            return new BigNumber(amount.replace('0x', ''), 16);

        return new BigNumber(amount.toString(10), 10);
    }

    static isAddress(address = false) {
        if (!tools.isString(address))
            return false;

        if (address.length === 46) {
            try {
                return GSCWeb3.isAddress(
                    tools.crypto.getBase58CheckAddress(
                        tools.code.hexStr2byteArray(address)
                    )
                );
            } catch (err) {
                return false;
            }
        }
        try {
            return tools.crypto.isAddressValid(address);
        } catch (err) {
            return false;
        }
    }

    static async createAccount() {
        const account = tools.accounts.generateAccount();
        return account;
    }

    async isConnected(callback = false) {
        if (!callback)
            return this.injectPromise(this.isConnected);
        return callback(null, {
            fullNode: await this.fullNode.isConnected(),
            confirmedNode: await this.confirmedNode.isConnected(),
            eventServer: this.eventServer && await this.eventServer.isConnected()
        });
    }
};
