import GSCWeb3 from 'index';
import tools from 'tools';
import {keccak256, toUtf8Bytes, recoverAddress, SigningKey} from 'tools/ethersUtils';
import {ADDRESS_PREFIX} from 'tools/address';
import Validator from "tools/paramValidator";

const GSC_MESSAGE_HEADER = '\x19GSC Signed Message:\n32';
const ETH_MESSAGE_HEADER = '\x19Ethereum Signed Message:\n32';

export default class Gsc {
    constructor(gscWeb3 = false) {
        if (!gscWeb3 || !gscWeb3 instanceof GSCWeb3)
            throw new Error('Expected instance of GSCWeb3');

        this.gscWeb3 = gscWeb3;
        this.injectPromise = tools.promiseInjector(this);
        this.cache = {
            contracts: {}
        }
        this.validator = new Validator(gscWeb3);
    }

    _getTransactionInfoById(transactionID, options, callback = false) {
        if (!callback)
            return this.injectPromise(this._getTransactionInfoById, transactionID, options);

        this.gscWeb3[options.confirmed ? 'confirmedNode' : 'fullNode'].request(`wallet${options.confirmed ? 'confirmed' : ''}/gettransactioninfobyid`, {
            value: transactionID
        }, 'post').then(transaction => {
            callback(null, transaction);
        }).catch(err => callback(err));
    }

    _parseToken(token) {
        return {
            ...token,
            name: this.gscWeb3.toUtf8(token.name),
            abbr: token.abbr && this.gscWeb3.toUtf8(token.abbr),
            description: token.description && this.gscWeb3.toUtf8(token.description),
            url: token.url && this.gscWeb3.toUtf8(token.url)
        };
    }

    getCurrentBlock(callback = false) {
        if (!callback)
            return this.injectPromise(this.getCurrentBlock);

        this.gscWeb3.fullNode.request('wallet/getnowblock').then(block => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getConfirmedCurrentBlock(callback = false) {
        if (!callback)
            return this.injectPromise(this.getConfirmedCurrentBlock);

        this.gscWeb3.confirmedNode.request('walletconfirmed/getnowblock').then(block => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlock(block = this.gscWeb3.defaultBlock, callback = false) {
        if (tools.isFunction(block)) {
            callback = block;
            block = this.gscWeb3.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getBlock, block);

        if (block === false)
            return callback('Error: code id: 20018');

        if (block == 'earliest')
            block = 0;

        if (block == 'latest')
            return this.getCurrentBlock(callback);

        if (isNaN(block) && tools.isHex(block))
            return this.getBlockByHash(block, callback);

        this.getBlockByNumber(block, callback);
    }

    getBlockByHash(blockHash, callback = false) {
        if (!callback)
            return this.injectPromise(this.getBlockByHash, blockHash);

        this.gscWeb3.fullNode.request('wallet/getblockbyid', {
            value: blockHash
        }, 'post').then(block => {
            if (!Object.keys(block).length)
                return callback('Block not found');

            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlockByNumber(blockID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getBlockByNumber, blockID);

        if (!tools.isInteger(blockID) || blockID < 0)
            return callback('Error: code id: 200019');

        this.gscWeb3.fullNode.request('wallet/getblockbynum', {
            num: parseInt(blockID)
        }, 'post').then(block => {
            if (!Object.keys(block).length)
                return callback('Block not found');

            callback(null, block);
        }).catch(err => callback(err));
    }

    getBlockTransactionCount(block = this.gscWeb3.defaultBlock, callback = false) {
        if (tools.isFunction(block)) {
            callback = block;
            block = this.gscWeb3.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getBlockTransactionCount, block);

        this.getBlock(block).then(({transactions = []}) => {
            callback(null, transactions.length);
        }).catch(err => callback(err));
    }

    getTransactionFromBlock(block = this.gscWeb3.defaultBlock, index, callback = false) {
        if (tools.isFunction(index)) {
            callback = index;
            index = 0;
        }

        if (tools.isFunction(block)) {
            callback = block;
            block = this.gscWeb3.defaultBlock;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionFromBlock, block, index);

        this.getBlock(block).then(({transactions = false}) => {
            if (!transactions)
                callback('Error: code id: 20020');
            else if (typeof index == 'number'){
                if (index >= 0 && index < transactions.length)
                    callback(null, transactions[index]);
                else
                    callback('Invalid transaction index provided');
            } else
                callback(null, transactions);
        }).catch(err => callback(err));
    }

    getTransaction(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTransaction, transactionID);

        this.gscWeb3.fullNode.request('wallet/gettransactionbyid', {
            value: transactionID
        }, 'post').then(transaction => {
            if (!Object.keys(transaction).length)
                return callback('Error: code id: 20021');

            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getConfirmedTransaction(transactionID, callback = false) {
        if (!callback)
            return this.injectPromise(this.getConfirmedTransaction, transactionID);

        this.gscWeb3.confirmedNode.request('walletconfirmed/gettransactionbyid', {
            value: transactionID
        }, 'post').then(transaction => {
            if (!Object.keys(transaction).length)
                return callback('Error: code id: 20021');

            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getUnconfirmedTransactionInfo(transactionID, callback = false) {
        return this._getTransactionInfoById(transactionID, {confirmed: false}, callback)
    }

    getTransactionInfo(transactionID, callback = false) {
        return this._getTransactionInfoById(transactionID, {confirmed: true}, callback)
    }

    getTransactionsToAddress(address = this.gscWeb3.defaultAddress.hex, limit = 30, offset = 0, callback = false) {
        if (tools.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (tools.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsToAddress, address, limit, offset);

        address = this.gscWeb3.address.toHex(address);

        return this.getTransactionsRelated(address, 'to', limit, offset, callback);
    }

    getTransactionsFromAddress(address = this.gscWeb3.defaultAddress.hex, limit = 30, offset = 0, callback = false) {
        if (tools.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (tools.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsFromAddress, address, limit, offset);

        address = this.gscWeb3.address.toHex(address);

        return this.getTransactionsRelated(address, 'from', limit, offset, callback);
    }

    async getTransactionsRelated(address = this.gscWeb3.defaultAddress.hex, direction = 'all', limit = 30, offset = 0, callback = false) {
        if (tools.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (tools.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }

        if (tools.isFunction(direction)) {
            callback = direction;
            direction = 'all';
        }

        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getTransactionsRelated, address, direction, limit, offset);

        if (!['to', 'from', 'all'].includes(direction))
            return callback('Error: code id: 20022');

        if (direction == 'all') {
            try {
                const [from, to] = await Promise.all([
                    this.getTransactionsRelated(address, 'from', limit, offset),
                    this.getTransactionsRelated(address, 'to', limit, offset)
                ])

                return callback(null, [
                    ...from.map(tx => (tx.direction = 'from', tx)),
                    ...to.map(tx => (tx.direction = 'to', tx))
                ].sort((a, b) => {
                    return b.raw_data.timestamp - a.raw_data.timestamp
                }));
            } catch (ex) {
                return callback(ex);
            }
        }

        if (!this.gscWeb3.isAddress(address))
            return callback('Error: code id: 20023');

        if (!tools.isInteger(limit) || limit < 0 || (offset && limit < 1))
            return callback('Error: code id: 20024');

        if (!tools.isInteger(offset) || offset < 0)
            return callback('Error: code id: 20025');

        address = this.gscWeb3.address.toHex(address);

        this.gscWeb3.confirmedNode.request(`walletextension/gettransactions${direction}this`, {
            account: {
                address
            },
            offset,
            limit
        }, 'post').then(({transaction}) => {
            callback(null, transaction);
        }).catch(err => callback(err));
    }

    getAccount(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getAccount, address);

        if (!this.gscWeb3.isAddress(address))
            return callback('Error: code id: 20023');

        address = this.gscWeb3.address.toHex(address);

        this.gscWeb3.confirmedNode.request('walletconfirmed/getaccount', {
            address
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getAccountById(id = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getAccountById, id);

        this.getAccountInfoById(id, {confirmed: true}, callback);
    }

    getAccountInfoById(id, options, callback) {
        if (this.validator.notValid([
            {
                name: 'accountId',
                type: 'hex',
                value: id
            },
            {
                name: 'accountId',
                type: 'string',
                lte: 32,
                gte: 8,
                value: id
            }
        ], callback))
            return;

        if (id.startsWith('0x')) {
            id = id.slice(2);
        }

        this.gscWeb3[options.confirmed ? 'confirmedNode' : 'fullNode'].request(`wallet${options.confirmed ? 'confirmed' : ''}/getaccountbyid`, {
            account_id: id
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getBalance(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getBalance, address);

        this.getAccount(address).then(({balance = 0}) => {
            callback(null, balance);
        }).catch(err => callback(err));
    }

    getUnconfirmedAccount(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getUnconfirmedAccount, address);

        if (!this.gscWeb3.isAddress(address))
            return callback('Error: code id: 20023');

        address = this.gscWeb3.address.toHex(address);

        this.gscWeb3.fullNode.request('wallet/getaccount', {
            address
        }, 'post').then(account => {
            callback(null, account);
        }).catch(err => callback(err));
    }

    getUnconfirmedAccountById(id, callback = false) {
        if (!callback)
            return this.injectPromise(this.getUnconfirmedAccountById, id);

        this.getAccountInfoById(id, {confirmed: false}, callback);
    }

    getUnconfirmedBalance(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getUnconfirmedBalance, address);

        this.getUnconfirmedAccount(address).then(({balance = 0}) => {
            callback(null, balance);
        }).catch(err => callback(err));
    }

    getNet(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getNet, address);

        if (!this.gscWeb3.isAddress(address))
            return callback('Error: code id: 20023');

        address = this.gscWeb3.address.toHex(address);

        this.gscWeb3.fullNode.request('wallet/getaccountnet', {
            address
        }, 'post').then(({freeNetUsed = 0, freeNetLimit = 0, NetUsed = 0, NetLimit = 0}) => {
            callback(null, (freeNetLimit - freeNetUsed) + (NetLimit - NetUsed));
        }).catch(err => callback(err));
    }

    getTokensIssuedByAddress(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.getTokensIssuedByAddress, address);

        if (!this.gscWeb3.isAddress(address))
            return callback('Error: code id: 20023');

        address = this.gscWeb3.address.toHex(address);

        this.gscWeb3.fullNode.request('wallet/getassetissuebyaccount', {
            address
        }, 'post').then(({assetIssue = false}) => {
            if (!assetIssue)
                return callback(null, {});

            const tokens = assetIssue.map(token => {
                return this._parseToken(token);
            }).reduce((tokens, token) => {
                return tokens[token.name] = token, tokens;
            }, {});

            callback(null, tokens);
        }).catch(err => callback(err));
    }

    getTokenFromID(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenFromID, tokenID);

        if (tools.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!tools.isString(tokenID) || !tokenID.length)
            return callback('Error: code id: 20026');

        this.gscWeb3.fullNode.request('wallet/getassetissuebyname', {
            value: this.gscWeb3.fromUtf8(tokenID)
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    getBlockRange(start = 0, end = 30, callback = false) {
        if (tools.isFunction(end)) {
            callback = end;
            end = 30;
        }

        if (tools.isFunction(start)) {
            callback = start;
            start = 0;
        }

        if (!callback)
            return this.injectPromise(this.getBlockRange, start, end);

        if (!tools.isInteger(start) || start < 0)
            return callback('Error: code id: 20027');

        if (!tools.isInteger(end) || end <= start)
            return callback('Error: code id: 20028');

        this.gscWeb3.fullNode.request('wallet/getblockbylimitnext', {
            startNum: parseInt(start),
            endNum: parseInt(end) + 1
        }, 'post').then(({block = []}) => {
            callback(null, block);
        }).catch(err => callback(err));
    }

    getContract(contractAddress, callback = false) {
        if (!callback)
            return this.injectPromise(this.getContract, contractAddress);

        if (!this.gscWeb3.isAddress(contractAddress))
            return callback('Error: code id: 20009');

        if (this.cache.contracts[contractAddress]) {
            callback(null, this.cache.contracts[contractAddress]);
            return;
        }

        contractAddress = this.gscWeb3.address.toHex(contractAddress);

        this.gscWeb3.fullNode.request('wallet/getcontract', {
            value: contractAddress
        }).then(contract => {
            if (contract.Error)
                return callback('Error: code id: 20029');
            this.cache.contracts[contractAddress] = contract;
            callback(null, contract);
        }).catch(err => callback(err));
    }

    async getApprovedList(transaction, callback = false) {
        if (!callback)
            return this.injectPromise(this.getApprovedList, transaction);

        if (!tools.isObject(transaction))
            return callback('Error: code id: 20030');


        this.gscWeb3.fullNode.request(
            'wallet/getapprovedlist',
            transaction,
            'post'
        ).then(result => {
            callback(null, result);
        }).catch(err => callback(err));
    }

    async getSignWeight(transaction, permissionId, callback = false) {
        if (tools.isFunction(permissionId)) {
            callback = permissionId;
            permissionId = undefined;
        }

        if (!callback)
            return this.injectPromise(this.getSignWeight, transaction, permissionId);

        if (!tools.isObject(transaction) || !transaction.raw_data || !transaction.raw_data.contract)
            return callback('Error: code id: 20030');

        if (tools.isInteger(permissionId)) {
            transaction.raw_data.contract[0].Permission_id = parseInt(permissionId);
        } else if (typeof transaction.raw_data.contract[0].Permission_id !== 'number') {
            transaction.raw_data.contract[0].Permission_id = 0;
        }

        if (!tools.isObject(transaction))
            return callback('Error: code id: 20030');


        this.gscWeb3.fullNode.request(
            'wallet/getsignweight',
            transaction,
            'post'
        ).then(result => {
            callback(null, result);
        }).catch(err => callback(err));
    }

    listNodes(callback = false) {
        if (!callback)
            return this.injectPromise(this.listNodes);

        this.gscWeb3.fullNode.request('wallet/listnodes').then(({nodes = []}) => {
            callback(null, nodes.map(({address: {host, port}}) => (
                `${this.gscWeb3.toUtf8(host)}:${port}`
            )));
        }).catch(err => callback(err));
    }

    listSuperRepresentatives(callback = false) {
        if (!callback)
            return this.injectPromise(this.listSuperRepresentatives);

        this.gscWeb3.fullNode.request('wallet/listwitnesses').then(({witnesses = []}) => {
            callback(null, witnesses);
        }).catch(err => callback(err));
    }

    listTokens(limit = 0, offset = 0, callback = false) {
        if (tools.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }

        if (tools.isFunction(limit)) {
            callback = limit;
            limit = 0;
        }

        if (!callback)
            return this.injectPromise(this.listTokens, limit, offset);

        if (!tools.isInteger(limit) || limit < 0 || (offset && limit < 1))
            return callback('Error: code id: 20024');

        if (!tools.isInteger(offset) || offset < 0)
            return callback('Error: code id: 20025');

        if (!limit) {
            return this.gscWeb3.fullNode.request('wallet/getassetissuelist').then(({assetIssue = []}) => {
                callback(null, assetIssue.map(token => this._parseToken(token)));
            }).catch(err => callback(err));
        }

        this.gscWeb3.fullNode.request('wallet/getpaginatedassetissuelist', {
            offset: parseInt(offset),
            limit: parseInt(limit)
        }, 'post').then(({assetIssue = []}) => {
            callback(null, assetIssue.map(token => this._parseToken(token)));
        }).catch(err => callback(err));
    }

    async verifyMessage(message = false, signature = false, address = this.gscWeb3.defaultAddress.base58, useGSCHeader = true, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.base58;
            useGSCHeader = true;
        }

        if (tools.isFunction(useGSCHeader)) {
            callback = useGSCHeader;
            useGSCHeader = true;
        }

        if (!callback)
            return this.injectPromise(this.verifyMessage, message, signature, address, useGSCHeader);

        if (!tools.isHex(message))
            return callback('Error: code id: 20031');

        if (GSC.verifySignature(message, address, signature, useGSCHeader))
            return callback(null, true);

        callback('Error: code id: 20032');
    }

    static verifySignature(message, address, signature, useGSCHeader = true) {
        message = message.replace(/^0x/,'');
        signature = signature.replace(/^0x/,'');
        const messageBytes = [
            ...toUtf8Bytes(useGSCHeader ? GSC_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...tools.code.hexStr2byteArray(message)
        ];

        const messageDigest = keccak256(messageBytes);
        const recovered = recoverAddress(messageDigest, {
            recoveryParam: signature.substring(128, 130) == '1c' ? 1 : 0,
            r: '0x' + signature.substring(0, 64),
            s: '0x' + signature.substring(64, 128)
        });

        const gscAddress = ADDRESS_PREFIX + recovered.substr(2);
        const base58Address = GSCWeb3.address.fromHex(gscAddress);

        return base58Address == GSCWeb3.address.fromHex(address);
    }

    async multiSign(transaction = false, privateKey = this.gscWeb3.defaultPrivateKey, permissionId = false, callback = false) {

        if (tools.isFunction(permissionId)) {
            callback = permissionId;
            permissionId = 0;
        }

        if (tools.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.gscWeb3.defaultPrivateKey;
            permissionId = 0;
        }

        if (!callback)
            return this.injectPromise(this.multiSign, transaction, privateKey, permissionId);

        if (!tools.isObject(transaction) || !transaction.raw_data || !transaction.raw_data.contract)
            return callback('Error: code id: 20030');

        if (!transaction.raw_data.contract[0].Permission_id && permissionId > 0) {
            transaction.raw_data.contract[0].Permission_id = permissionId;

            const address = this.gscWeb3.address.toHex(this.gscWeb3.address.fromPrivateKey(privateKey)).toLowerCase();
            const signWeight = await this.getSignWeight(transaction, permissionId);

            if (signWeight.result.code === 'PERMISSION_ERROR') {
                return callback(signWeight.result.message);
            }

            let foundKey = false;
            signWeight.permission.keys.map(key => {
                if (key.address === address)
                    foundKey = true;
            });

            if (!foundKey)
                return callback(privateKey + ' has no permission to sign');

            if (signWeight.approved_list && signWeight.approved_list.indexOf(address) != -1) {
                return callback(privateKey + ' already sign transaction');
            }

            if (signWeight.transaction && signWeight.transaction.transaction) {
                transaction = signWeight.transaction.transaction;
                if (permissionId > 0) {
                    transaction.raw_data.contract[0].Permission_id = permissionId;
                }
            } else {
                return callback('Error: code id: 20030');
            }
        }

        try {
            return callback(null, tools.crypto.signTransaction(privateKey, transaction));
        } catch (ex) {
            callback(ex);
        }
    }

    broadcast(...args) {
        return this.sendRawTransaction(...args);
    }

    sendRawTransaction(signedTransaction = false, options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this.sendRawTransaction, signedTransaction, options);

        if (!tools.isObject(signedTransaction))
            return callback('Error: code id: 20030');

        if (!tools.isObject(options))
            return callback('Error: code id: 20005');

        if (!signedTransaction.signature || !tools.isArray(signedTransaction.signature))
            return callback('Error: code id: 20033');

        this.gscWeb3.fullNode.request(
            'wallet/broadcasttransaction',
            signedTransaction,
            'post'
        ).then(result => {
            if (result.result)
                result.transaction = signedTransaction;
            callback(null, result);
        }).catch(err => callback(err));
    }

    send(...args) {
        return this.sendTransaction(...args);
    }

    sendGSC(...args) {
        return this.sendTransaction(...args);
    }

    async sendTransaction(to = false, amount = false, options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.sendTransaction, to, amount, options);

        if (!this.gscWeb3.isAddress(to))
            return callback('Error: code id: 20034');

        if (!tools.isInteger(amount) || amount <= 0)
            return callback('Error: code id: 20035');

        options = {
            privateKey: this.gscWeb3.defaultPrivateKey,
            address: this.gscWeb3.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Error: code id: 20036');

        try {
            const address = options.privateKey ? this.gscWeb3.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.gscWeb3.transactionBuilder.sendGSC(to, amount, address);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    sendAsset(...args) {
        return this.sendToken(...args);
    }

    async sendToken(to = false, amount = false, tokenID = false, options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.sendToken, to, amount, tokenID, options);

        if (!this.gscWeb3.isAddress(to))
            return callback('Error: code id: 20034');

        if (!tools.isInteger(amount) || amount <= 0)
            return callback('Error: code id: 20035');

        if (tools.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!tools.isString(tokenID))
            return callback('Error: code id: 20026');

        options = {
            privateKey: this.gscWeb3.defaultPrivateKey,
            address: this.gscWeb3.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Error: code id: 20036');

        try {
            const address = options.privateKey ? this.gscWeb3.address.fromPrivateKey(options.privateKey) : options.address;
            const transaction = await this.gscWeb3.transactionBuilder.sendToken(to, amount, tokenID, address);
            const signedTransaction = await this.sign(transaction, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    signMessage(...args) {
        return this.sign(...args);
    }

    signTransaction(...args) {
        return this.sign(...args);
    }

    async sign(transaction = false, privateKey = this.gscWeb3.defaultPrivateKey, useGSCHeader = true, multisig = false, callback = false) {

        if (tools.isFunction(multisig)) {
            callback = multisig;
            multisig = false;
        }

        if (tools.isFunction(useGSCHeader)) {
            callback = useGSCHeader;
            useGSCHeader = true;
            multisig = false;
        }

        if (tools.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.gscWeb3.defaultPrivateKey;
            useGSCHeader = true;
            multisig = false;
        }


        if (!callback)
            return this.injectPromise(this.sign, transaction, privateKey, useGSCHeader, multisig);

        if (tools.isString(transaction)) {

            if (!tools.isHex(transaction))
                return callback('Error: code id: 20030');

            try {
                const signatureHex = GSC.signString(transaction, privateKey, useGSCHeader)
                return callback(null, signatureHex);
            } catch (ex) {
                callback(ex);
            }
        }

        if (!tools.isObject(transaction))
            return callback('Error: code id: 20037');

        if (!multisig && transaction.signature)
            return callback('Error: code id: 20038');

        try {
            if (!multisig) {
                const address = this.gscWeb3.address.toHex(
                    this.gscWeb3.address.fromPrivateKey(privateKey)
                ).toLowerCase();

                if (address !== transaction.raw_data.contract[0].parameter.value.owner_address.toLowerCase())
                    return callback('Error: code id: 20039');
            }
            return callback(null,
                tools.crypto.signTransaction(privateKey, transaction)
            );
        } catch (ex) {
            callback(ex);
        }
    }

    static signString(message, privateKey, useGSCHeader = true) {
        message = message.replace(/^0x/,'');
        const signingKey = new SigningKey(privateKey);
        const messageBytes = [
            ...toUtf8Bytes(useGSCHeader ? GSC_MESSAGE_HEADER : ETH_MESSAGE_HEADER),
            ...tools.code.hexStr2byteArray(message)
        ];

        const messageDigest = keccak256(messageBytes);
        const signature = signingKey.signDigest(messageDigest);

        const signatureHex = [
            '0x',
            signature.r.substring(2),
            signature.s.substring(2),
            Number(signature.v).toString(16)
        ].join('');

        return signatureHex
    }

    timeUntilNextVoteCycle(callback = false) {
        if (!callback)
            return this.injectPromise(this.timeUntilNextVoteCycle);

        this.gscWeb3.fullNode.request('wallet/getnextmaintenancetime').then(({num = -1}) => {
            if (num == -1)
                return callback('Error: code id: 20040');

            callback(null, Math.floor(num / 1000));
        }).catch(err => callback(err));
    }

    async freezeBalance(amount = 0, duration = 3, resource = "NET", options = {}, receiverAddress = undefined, callback = false) {
        if (tools.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }
        if (tools.isFunction(duration)) {
            callback = duration;
            duration = 3;
        }

        if (tools.isFunction(resource)) {
            callback = resource;
            resource = "NET";
        }

        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.freezeBalance, amount, duration, resource, options, receiverAddress);

        if (!['NET', 'CPU'].includes(resource))
            return callback('Error: code id: 20041');

        if (!tools.isInteger(amount) || amount <= 0)
            return callback('Error: code id: 20035');

        if (!tools.isInteger(duration) || duration < 3)
            return callback('Error: code id: 20042');

        options = {
            privateKey: this.gscWeb3.defaultPrivateKey,
            address: this.gscWeb3.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Error: code id: 20036');

        try {
            const address = options.privateKey ? this.gscWeb3.address.fromPrivateKey(options.privateKey) : options.address;
            const freezeBalance = await this.gscWeb3.transactionBuilder.freezeBalance(amount, duration, resource, address, receiverAddress);
            const signedTransaction = await this.sign(freezeBalance, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    async unfreezeBalance(resource = "NET", options = {}, receiverAddress = undefined, callback = false) {
        if (tools.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        }

        if (tools.isFunction(resource)) {
            callback = resource;
            resource = 'NET';
        }

        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback)
            return this.injectPromise(this.unfreezeBalance, resource, options, receiverAddress);

        if (!['NET', 'CPU'].includes(resource))
            return callback('Error: code id: 20041');

        options = {
            privateKey: this.gscWeb3.defaultPrivateKey,
            address: this.gscWeb3.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Error: code id: 20036');

        try {
            const address = options.privateKey ? this.gscWeb3.address.fromPrivateKey(options.privateKey) : options.address;
            const unfreezeBalance = await this.gscWeb3.transactionBuilder.unfreezeBalance(resource, address, receiverAddress);
            const signedTransaction = await this.sign(unfreezeBalance, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    async updateAccount(accountName = false, options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (typeof options === 'string')
            options = {privateKey: options};

        if (!callback) {
            return this.injectPromise(this.updateAccount, accountName, options);
        }

        if (!tools.isString(accountName) || !accountName.length) {
            return callback('Error: code id: 20043');
        }

        options = {
            privateKey: this.gscWeb3.defaultPrivateKey,
            address: this.gscWeb3.defaultAddress.hex,
            ...options
        };

        if (!options.privateKey && !options.address)
            return callback('Error: code id: 20036');

        try {
            const address = options.privateKey ? this.gscWeb3.address.fromPrivateKey(options.privateKey) : options.address;
            const updateAccount = await this.gscWeb3.transactionBuilder.updateAccount(accountName, address);
            const signedTransaction = await this.sign(updateAccount, options.privateKey || undefined);
            const result = await this.sendRawTransaction(signedTransaction);

            return callback(null, result);
        } catch (ex) {
            return callback(ex);
        }
    }

    listProposals(callback = false) {
        if (!callback)
            return this.injectPromise(this.listProposals);

        this.gscWeb3.fullNode.request('wallet/listproposals', {}, 'post').then(({proposals = []}) => {
            callback(null, proposals);
        }).catch(err => callback(err));
    }

    listExchangesPaginated(limit = 10, offset = 0, callback = false) {
        if (tools.isFunction(offset)) {
            callback = offset;
            offset = 0;
        }
        if (tools.isFunction(limit)) {
            callback = limit;
            limit = 30;
        }
        if (!callback)
            return this.injectPromise(this.listExchanges);

        this.gscWeb3.fullNode.request('wallet/listexchangespaginated', {
            limit,
            offset
        }, 'post').then(({exchanges = []}) => {
            callback(null, exchanges);
        }).catch(err => callback(err));
    }

    listExchanges(callback = false) {
        if (!callback)
            return this.injectPromise(this.listExchanges);

        this.gscWeb3.fullNode.request('wallet/listexchanges', {}, 'post').then(({exchanges = []}) => {
            callback(null, exchanges);
        }, 'post').catch(err => callback(err));
    }

    getProposal(proposalID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getProposal, proposalID);

        if (!tools.isInteger(proposalID) || proposalID < 0)
            return callback('Error: code id: 20044');

        this.gscWeb3.fullNode.request('wallet/getproposalbyid', {
            id: parseInt(proposalID),
        }, 'post').then(proposal => {
            callback(null, proposal);
        }).catch(err => callback(err));
    }

    getChainParameters(callback = false) {
        if (!callback)
            return this.injectPromise(this.getChainParameters);

        this.gscWeb3.fullNode.request('wallet/getchainparameters', {}, 'post').then(({chainParameter = []}) => {
            callback(null, chainParameter);
        }).catch(err => callback(err));
    }

    getAccountResources(address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (!callback)
            return this.injectPromise(this.getAccountResources, address);

        if (!this.gscWeb3.isAddress(address))
            return callback('Error: code id: 20023');

        this.gscWeb3.fullNode.request('wallet/getaccountresource', {
            address: this.gscWeb3.address.toHex(address),
        }, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    getExchangeByID(exchangeID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getExchangeByID, exchangeID);

        if (!tools.isInteger(exchangeID) || exchangeID < 0)
            return callback('Error: code id: 20045');

        this.gscWeb3.fullNode.request('wallet/getexchangebyid', {
            id: exchangeID,
        }, 'post').then(exchange => {
            callback(null, exchange);
        }).catch(err => callback(err));
    }

    getNodeInfo(callback = false) {
        if (!callback)
            return this.injectPromise(this.getNodeInfo);

        this.gscWeb3.fullNode.request('wallet/getnodeinfo', {}, 'post').then(info => {
            callback(null, info);
        }, 'post').catch(err => callback(err));
    }

    getTokenListByName(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenListByName, tokenID);

        if (tools.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!tools.isString(tokenID) || !tokenID.length)
            return callback('Error: code id: 20026');

        this.gscWeb3.fullNode.request('wallet/getassetissuelistbyname', {
            value: this.gscWeb3.fromUtf8(tokenID)
        }, 'post').then(token => {
            if (!token.name)
                return callback('Error: code id: 20046');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

    getTokenByID(tokenID = false, callback = false) {
        if (!callback)
            return this.injectPromise(this.getTokenByID, tokenID);

        if (tools.isInteger(tokenID))
            tokenID = tokenID.toString()

        if (!tools.isString(tokenID) || !tokenID.length)
            return callback('Error: code id: 20026');

        this.gscWeb3.fullNode.request('wallet/getassetissuebyid', {
            value: tokenID
        }, 'post').then(token => {
            if (!token.name)
                return callback('Token does not exist');

            callback(null, this._parseToken(token));
        }).catch(err => callback(err));
    }

};
