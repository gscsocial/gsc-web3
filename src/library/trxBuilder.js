import GSCWeb3 from 'index';
import tools from 'tools';
import {AbiCoder} from 'tools/ethersUtils';
import Validator from 'tools/paramValidator';
import {ADDRESS_PREFIX_REGEX} from 'tools/address';

let self;

function fromUtf8(value) {
    return self.gscWeb3.fromUtf8(value);
}

function toHex(value) {
    return self.gscWeb3.address.toHex(value);
}

function resultManager(transaction, callback) {
    if (transaction.Error)
        return callback(transaction.Error);

    if (transaction.result && transaction.result.message) {
        return callback(
            self.gscWeb3.toUtf8(transaction.result.message)
        );
    }

    return callback(null, transaction);
}


export default class TransactionBuilder {
    constructor(gscWeb3 = false) {
        if (!gscWeb3 || !gscWeb3 instanceof GSCWeb3)
            throw new Error('Expected instance of GSCWeb3');
        self = this;
        this.gscWeb3 = gscWeb3;
        this.injectPromise = tools.promiseInjector(this);
        this.validator = new Validator(gscWeb3);
    }

    _triggerSmartContract(
        contractAddress,
        functionSelector,
        options = {},
        parameters = [],
        issuerAddress = this.gscWeb3.defaultAddress.hex,
        callback = false
    ) {

        if (tools.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (tools.isFunction(parameters)) {
            callback = parameters;
            parameters = [];
        }

        if (!callback) {
            return this.injectPromise(
                this._triggerSmartContract,
                contractAddress,
                functionSelector,
                options,
                parameters,
                issuerAddress
            );
        }

        let {
            tokenValue,
            tokenId,
            callValue,
            feeLimit,
        } = Object.assign({
            callValue: 0,
            feeLimit: 1_000_000_000
        }, options)

        if (this.validator.notValid([
            {
                name: 'feeLimit',
                type: 'integer',
                value: feeLimit,
                gt: 0,
                lte: 1_000_000_000
            },
            {
                name: 'callValue',
                type: 'integer',
                value: callValue,
                gte: 0
            },
            {
                name: 'parameters',
                type: 'array',
                value: parameters
            },
            {
                name: 'contract',
                type: 'address',
                value: contractAddress
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress,
                optional: true
            },
            {
                name: 'tokenValue',
                type: 'integer',
                value: tokenValue,
                gte: 0,
                optional: true
            },
            {
                name: 'tokenId',
                type: 'integer',
                value: tokenId,
                gte: 0,
                optional: true
            },
            {
                name: 'function selector',
                type: 'not-empty-string',
                value: functionSelector
            }
        ], callback))
            return;

        functionSelector = functionSelector.replace('/\s*/g', '');

        if (parameters.length) {
            const abiCoder = new AbiCoder();
            let types = [];
            const values = [];

            for (let i = 0; i < parameters.length; i++) {
                let {type, value} = parameters[i];

                if (!type || !tools.isString(type) || !type.length)
                    return callback('Error: code id: 20001' + type);

                if (type == 'address')
                    value = toHex(value).replace(ADDRESS_PREFIX_REGEX, '0x');

                types.push(type);
                values.push(value);
            }

            try {
                // workaround for unsupported trcToken type
                types = types.map(type => {
                    if (/trcToken/.test(type)) {
                        type = type.replace(/trcToken/, 'uint256')
                    }
                    return type
                })

                parameters = abiCoder.encode(types, values).replace(/^(0x)/, '');
            } catch (ex) {
                return callback(ex);
            }
        } else parameters = '';

        const args = {
            contract_address: toHex(contractAddress),
            owner_address: toHex(issuerAddress),
            function_selector: functionSelector,
            parameter: parameters
        };

        if (!options._isConstant) {
            args.call_value = parseInt(callValue)
            args.fee_limit = parseInt(feeLimit)
            if (tools.isNotNullOrUndefined(tokenValue))
                args.call_token_value = parseInt(tokenValue)
            if (tools.isNotNullOrUndefined(tokenId))
                args.token_id = parseInt(tokenId)
        }

        if (options.permissionId) {
            args.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request(`wallet/trigger${options._isConstant ? 'constant' : 'smart'}contract`, args, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    applyForSR(address = this.gscWeb3.defaultAddress.hex, url = false, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isValidURL(address)) {
            callback = url || false;
            url = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (tools.isObject(url)) {
            address = this.gscWeb3.defaultAddress.hex;
            url = address;
            options = url;
        }

        if (!callback)
            return this.injectPromise(this.applyForSR, address, url, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            },
            {
                name: 'url',
                type: 'url',
                value: url,
                msg: 'Invalid url provided'
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address),
            url: fromUtf8(url)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/createwitness', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    async alterTransaction(transaction, options = {}, callback = false) {
        if (!callback)
            return this.injectPromise(this.alterTransaction, transaction, options);

        if (transaction.signature)
            return callback('Error: code id: 20002')

        if (options.data) {
            if (options.dataFormat !== 'hex')
                options.data = this.gscWeb3.toHex(options.data);
            options.data = options.data.replace(/^0x/, '')
            if (options.data.length === 0)
                return callback('Invalid data provided');
            transaction.raw_data.data = options.data;
        }

        if (options.extension) {
            options.extension = parseInt(options.extension * 1000);
            if (isNaN(options.extension) || transaction.raw_data.expiration + options.extension <= Date.now() + 3000)
                return callback('Error: code id: 20003');
            transaction.raw_data.expiration += options.extension;
        }

        this.newTxID(transaction, callback)
    }

    async addUpdateData(transaction, data, dataFormat = 'utf8', callback = false) {

        if (tools.isFunction(dataFormat)) {
            callback = dataFormat;
            dataFormat = 'utf8';
        }

        if (!callback)
            return this.injectPromise(this.addUpdateData, transaction, data, dataFormat);

        this.alterTransaction(transaction, {data, dataFormat}, callback);
    }

    checkPermissions(permissions, type) {
        if (permissions) {
            if (permissions.type !== type
                || !permissions.permission_name
                || !tools.isString(permissions.permission_name)
                || !tools.isInteger(permissions.threshold)
                || permissions.threshold < 1
                || !permissions.keys
            ) {
                return false
            }
            for (let key of permissions.keys) {
                if (!this.gscWeb3.isAddress(key.address)
                    || !tools.isInteger(key.weight)
                    || key.weight > permissions.threshold
                    || key.weight < 1
                    || (type === 2 && !permissions.operations)
                ) {
                    return false
                }
            }
        }
        return true
    }

    async extendExpiration(transaction, extension, callback = false) {
        if (!callback)
            return this.injectPromise(this.extendExpiration, transaction, extension);

        this.alterTransaction(transaction, {extension}, callback);
    }

    async newTxID(transaction, callback) {

        if (!callback)
            return this.injectPromise(this.newTxID, transaction);

        this.gscWeb3.fullNode
            .request(
                'wallet/getsignweight',
                transaction,
                'post'
            )
            .then(newTransaction => {
                newTransaction = newTransaction.transaction.transaction
                if (typeof transaction.visible === 'boolean') {
                    newTransaction.visible = transaction.visible
                }
                callback(null, newTransaction)
            })
            .catch(err => callback('Error: code id: 20004'));
    }

    createSmartContract(options = {}, issuerAddress = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createSmartContract, options, issuerAddress);

        const feeLimit = options.feeLimit || 1_000_000_000;
        let userFeePercentage = options.userFeePercentage;
        if (typeof userFeePercentage !== 'number' && !userFeePercentage) {
            userFeePercentage = 100;
        }
        const originCpuLimit = options.originCpuLimit || 10_000_000;
        const callValue = options.callValue || 0;
        const tokenValue = options.tokenValue;
        const tokenId = options.tokenId || options.token_id;

        let {
            abi = false,
            bytecode = false,
            parameters = [],
            name = ""
        } = options;

        if (abi && tools.isString(abi)) {
            try {
                abi = JSON.parse(abi);
            } catch {
                return callback('Error: code id: 20005');
            }
        }

        if (abi.entrys)
            abi = abi.entrys;

        if (!tools.isArray(abi))
            return callback('Error: code id: 20005');


        const payable = abi.some(func => {
            return func.type == 'constructor' && func.payable;
        });

        if (this.validator.notValid([
            {
                name: 'bytecode',
                type: 'hex',
                value: bytecode
            },
            {
                name: 'feeLimit',
                type: 'integer',
                value: feeLimit,
                gt: 0,
                lte: 1_000_000_000
            },
            {
                name: 'callValue',
                type: 'integer',
                value: callValue,
                gte: 0
            },
            {
                name: 'userFeePercentage',
                type: 'integer',
                value: userFeePercentage,
                gte: 0,
                lte: 100
            },
            {
                name: 'originCpuLimit',
                type: 'integer',
                value: originCpuLimit,
                gte: 0,
                lte: 10_000_000
            },
            {
                name: 'parameters',
                type: 'array',
                value: parameters
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'tokenValue',
                type: 'integer',
                value: tokenValue,
                gte: 0,
                optional: true
            },
            {
                name: 'tokenId',
                type: 'integer',
                value: tokenId,
                gte: 0,
                optional: true
            }
        ], callback))
            return;

        if (payable && callValue == 0 && tokenValue == 0)
            return callback('Error: code id: 20006');

        if (!payable && (callValue > 0 || tokenValue > 0))
            return callback('Error: code id: 20007');


        var constructorParams = abi.find(
            (it) => {
                return it.type === 'constructor';
            }
        );

        if (typeof constructorParams !== 'undefined' && constructorParams) {
            const abiCoder = new AbiCoder();
            const types = [];
            const values = [];
            constructorParams = constructorParams.inputs;

            if (parameters.length != constructorParams.length)
                return callback('Error: code id: 20008');

            for (let i = 0; i < parameters.length; i++) {
                let type = constructorParams[i].type;
                let value = parameters[i];

                if (!type || !tools.isString(type) || !type.length)
                    return callback('Error: code id: 20001' + type);

                if (type == 'address')
                    value = toHex(value).replace(ADDRESS_PREFIX_REGEX, '0x');

                types.push(type);
                values.push(value);
            }

            try {
                parameters = abiCoder.encode(types, values).replace(/^(0x)/, '');
            } catch (ex) {
                return callback(ex);
            }
        } else parameters = '';

        const args = {
            owner_address: toHex(issuerAddress),
            fee_limit: parseInt(feeLimit),
            call_value: parseInt(callValue),
            consume_user_resource_percent: userFeePercentage,
            origin_cpu_limit: originCpuLimit,
            abi: JSON.stringify(abi),
            bytecode,
            parameter: parameters,
            name
        };

        if (tools.isNotNullOrUndefined(tokenValue))
            args.call_token_value = parseInt(tokenValue)
        if (tools.isNotNullOrUndefined(tokenId))
            args.token_id = parseInt(tokenId)
        if (options && options.permissionId)
            args.Permission_id = options.permissionId;

        this.gscWeb3.fullNode.request('wallet/deploycontract', args, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    clearABI(contractAddress, ownerAddress = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (!callback)
            return this.injectPromise(this.clearABI, contractAddress, ownerAddress);

        if (!this.gscWeb3.isAddress(contractAddress))
            return callback('Error: code id: 20009');

        if (!this.gscWeb3.isAddress(ownerAddress))
            return callback('Error: code id: 20010');

        const data = {
            contract_address: toHex(contractAddress),
            owner_address: toHex(ownerAddress)
        };

        if (this.gscWeb3.gsc.cache.contracts[contractAddress]) {
            delete this.gscWeb3.gsc.cache.contracts[contractAddress]
        }
        this.gscWeb3.fullNode.request('wallet/clearabi', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));

    }

    createAsset(...args) {
        return this.createToken(...args);
    }

    createToken(options = {}, issuerAddress = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createToken, options, issuerAddress);

        const {
            name = false,
            abbreviation = false,
            description = false,
            url = false,
            totalSupply = 0,
            gscRatio = 1,
            tokenRatio = 1,
            saleStart = Date.now(),
            saleEnd = false,
            freeNet = 0,
            freeNetLimit = 0,
            frozenAmount = 0,
            frozenDuration = 0,
            voteScore,
            precision
        } = options;

        if (this.validator.notValid([
            {
                name: 'Supply amount',
                type: 'positive-integer',
                value: totalSupply
            },
            {
                name: 'GSC ratio',
                type: 'positive-integer',
                value: gscRatio
            },
            {
                name: 'Token ratio',
                type: 'positive-integer',
                value: tokenRatio
            },
            {
                name: 'token abbreviation',
                type: 'not-empty-string',
                value: abbreviation
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: name
            },
            {
                name: 'token description',
                type: 'not-empty-string',
                value: description
            },
            {
                name: 'token url',
                type: 'url',
                value: url
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'sale start timestamp',
                type: 'integer',
                value: saleStart,
                gte: Date.now()
            },
            {
                name: 'sale end timestamp',
                type: 'integer',
                value: saleEnd,
                gt: saleStart
            },
            {
                name: 'Free Net amount',
                type: 'integer',
                value: freeNet,
                gte: 0
            },
            {
                name: 'Free Net limit',
                type: 'integer',
                value: freeNetLimit,
                gte: 0
            },
            {
                name: 'Frozen supply',
                type: 'integer',
                value: frozenAmount,
                gte: 0
            },
            {
                name: 'Frozen duration',
                type: 'integer',
                value: frozenDuration,
                gte: 0
            }
        ], callback))
            return;

        if (tools.isNotNullOrUndefined(voteScore) && (!tools.isInteger(voteScore) || voteScore <= 0))
            return callback('Error: code id: 20011');

        if (tools.isNotNullOrUndefined(precision) && (!tools.isInteger(precision) || precision <= 0 || precision > 6))
            return callback('Error: code id: 20012');

        const data = {
            owner_address: toHex(issuerAddress),
            name: fromUtf8(name),
            abbr: fromUtf8(abbreviation),
            description: fromUtf8(description),
            url: fromUtf8(url),
            total_supply: parseInt(totalSupply),
            gsc_num: parseInt(gscRatio),
            num: parseInt(tokenRatio),
            start_time: parseInt(saleStart),
            end_time: parseInt(saleEnd),
            free_asset_net_limit: parseInt(freeNet),
            public_free_asset_net_limit: parseInt(freeNetLimit),
            frozen_supply: {
                frozen_amount: parseInt(frozenAmount),
                frozen_days: parseInt(frozenDuration)
            }
        }
        if (this.gscWeb3.fullnodeSatisfies('>=3.5.0') && !(parseInt(frozenAmount) > 0)) {
            delete data.frozen_supply
        }
        if (precision && !isNaN(parseInt(precision))) {
            data.precision = parseInt(precision);
        }
        if (voteScore && !isNaN(parseInt(voteScore))) {
            data.vote_score = parseInt(voteScore)
        }
        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/createassetissue', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    freezeBalance(amount = 0, duration = 3, resource = "NET", address = this.gscWeb3.defaultAddress.hex, receiverAddress = undefined, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        } else if (tools.isObject(receiverAddress)) {
            options = receiverAddress;
            receiverAddress = undefined;
        }

        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(address)) {
            options = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (tools.isFunction(duration)) {
            callback = duration;
            duration = 3;
        }

        if (tools.isFunction(resource)) {
            callback = resource;
            resource = "NET";
        }

        if (!callback)
            return this.injectPromise(this.freezeBalance, amount, duration, resource, address, receiverAddress, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            },
            {
                name: 'receiver',
                type: 'address',
                value: receiverAddress,
                optional: true
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'duration',
                type: 'integer',
                gte: 3,
                value: duration
            },
            {
                name: 'resource',
                type: 'resource',
                value: resource,
                msg: 'Invalid resource provided: Expected "NET" or "CPU"'
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address),
            frozen_balance: parseInt(amount),
            frozen_duration: parseInt(duration),
            resource: resource
        }

        if (tools.isNotNullOrUndefined(receiverAddress) && toHex(receiverAddress) !== toHex(address)) {
            data.receiver_address = toHex(receiverAddress)
        }

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/freezebalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    unfreezeBalance(resource = "NET", address = this.gscWeb3.defaultAddress.hex, receiverAddress = undefined, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(receiverAddress)) {
            callback = receiverAddress;
            receiverAddress = undefined;
        } else if (tools.isObject(receiverAddress)) {
            options = receiverAddress;
            receiverAddress = undefined;
        }

        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(address)) {
            options = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (tools.isFunction(resource)) {
            callback = resource;
            resource = "NET";
        }

        if (!callback)
            return this.injectPromise(this.unfreezeBalance, resource, address, receiverAddress, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            },
            {
                name: 'receiver',
                type: 'address',
                value: receiverAddress,
                optional: true
            },
            {
                name: 'resource',
                type: 'resource',
                value: resource,
                msg: 'Invalid resource provided: Expected "NET" or "CPU"'
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address),
            resource: resource
        }

        if (tools.isNotNullOrUndefined(receiverAddress) && toHex(receiverAddress) !== toHex(address)) {
            data.receiver_address = toHex(receiverAddress)
        }

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/unfreezebalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }


    purchaseAsset(...args) {
        return this.purchaseToken(...args);
    }

    purchaseToken(issuerAddress = false, tokenID = false, amount = 0, buyer = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(buyer)) {
            callback = buyer;
            buyer = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(buyer)) {
            options = buyer;
            buyer = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.purchaseToken, issuerAddress, tokenID, amount, buyer, options);

        if (this.validator.notValid([
            {
                name: 'buyer',
                type: 'address',
                value: buyer
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                names: ['buyer', 'issuer'],
                type: 'notEqual',
                msg: 'Cannot purchase tokens from same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token ID',
                type: 'tokenId',
                value: tokenID
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(issuerAddress),
            owner_address: toHex(buyer),
            asset_name: fromUtf8(tokenID),
            amount: parseInt(amount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/participateassetissue', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    withdrawBlockRewards(address = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(address)) {
            options = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.withdrawBlockRewards, address, options);

        if (this.validator.notValid([
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(address)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/withdrawbalance', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    vote(votes = {}, voterAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(voterAddress)) {
            callback = voterAddress;
            voterAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(voterAddress)) {
            options = voterAddress;
            voterAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.vote, votes, voterAddress, options);

        if (this.validator.notValid([
            {
                name: 'voter',
                type: 'address',
                value: voterAddress
            },
            {
                name: 'votes',
                type: 'notEmptyObject',
                value: votes
            }
        ], callback))
            return;

        let invalid = false;

        votes = Object.entries(votes).map(([srAddress, voteCount]) => {
            if (invalid)
                return;

            if (this.validator.notValid([
                {
                    name: 'SR',
                    type: 'address',
                    value: srAddress
                },
                {
                    name: 'vote count',
                    type: 'integer',
                    gt: 0,
                    value: voteCount,
                    msg: 'Invalid vote count provided for SR: ' + srAddress
                }
            ]))
                return invalid = true;

            return {
                vote_address: toHex(srAddress),
                vote_count: parseInt(voteCount)
            };
        });

        if (invalid)
            return;

        const data = {
            owner_address: toHex(voterAddress),
            votes,
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/votewitnessaccount', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    triggerSmartContract(...params) {
        if (typeof params[2] !== 'object') {
            params[2] = {
                feeLimit: params[2],
                callValue: params[3]
            }
            params.splice(3, 1)
        }
        return this._triggerSmartContract(...params);
    }

    triggerConstantContract(...params) {
        params[2]._isConstant = true
        return this.triggerSmartContract(...params);
    }

    updateAccount(accountName = false, address = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(address)) {
            options = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback) {
            return this.injectPromise(this.updateAccount, accountName, address, options);
        }

        if (this.validator.notValid([
            {
                name: 'Name',
                type: 'not-empty-string',
                value: accountName
            },
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;

        const data = {
            account_name: fromUtf8(accountName),
            owner_address: toHex(address),
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/updateaccount', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    setAccountId(accountId, address = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(address)) {
            callback = address;
            address = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback) {
            return this.injectPromise(this.setAccountId, accountId, address);
        }

        if (accountId && tools.isString(accountId) && accountId.startsWith('0x')) {
            accountId = accountId.slice(2);
        }

        if (this.validator.notValid([
            {
                name: 'accountId',
                type: 'hex',
                value: accountId
            },
            {
                name: 'accountId',
                type: 'string',
                lte: 32,
                gte: 8,
                value: accountId
            },
            {
                name: 'origin',
                type: 'address',
                value: address
            }
        ], callback))
            return;


        this.gscWeb3.fullNode.request('wallet/setaccountid', {
            account_id: accountId,
            owner_address: toHex(address),
        }, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendGSC(to = false, amount = 0, from = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(from)) {
            callback = from;
            from = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(from)) {
            options = from;
            from = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.sendGSC, to, amount, from, options);

        // accept amounts passed as strings
        amount = parseInt(amount)

        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer gsc to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(to),
            owner_address: toHex(from),
            amount: amount,
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/createtransaction', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    sendAsset(...args) {
        return this.sendToken(...args);
    }

    sendToken(to = false, amount = 0, tokenID = false, from = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(from)) {
            callback = from;
            from = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(from)) {
            options = from;
            from = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.sendToken, to, amount, tokenID, from, options);

        amount = parseInt(amount)
        if (this.validator.notValid([
            {
                name: 'recipient',
                type: 'address',
                value: to
            },
            {
                name: 'origin',
                type: 'address',
                value: from,
            },
            {
                names: ['recipient', 'origin'],
                type: 'notEqual',
                msg: 'Cannot transfer tokens to the same account'
            },
            {
                name: 'amount',
                type: 'integer',
                gt: 0,
                value: amount
            },
            {
                name: 'token ID',
                type: 'tokenId',
                value: tokenID
            }
        ], callback))
            return;

        const data = {
            to_address: toHex(to),
            owner_address: toHex(from),
            asset_name: fromUtf8(tokenID),
            amount: parseInt(amount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/transferasset', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateAsset(...args) {
        return this.updateToken(...args);
    }

    updateToken(options = {}, issuerAddress = this.gscWeb3.defaultAddress.hex, callback = false) {
        if (tools.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(issuerAddress)) {
            options = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateToken, options, issuerAddress);

        const {
            description = false,
            url = false,
            freeNet = 0,
            freeNetLimit = 0
        } = options;


        if (this.validator.notValid([
            {
                name: 'token description',
                type: 'not-empty-string',
                value: description
            },
            {
                name: 'token url',
                type: 'url',
                value: url
            },
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'Free Net amount',
                type: 'positive-integer',
                value: freeNet
            },
            {
                name: 'Free Net limit',
                type: 'positive-integer',
                value: freeNetLimit
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(issuerAddress),
            description: fromUtf8(description),
            url: fromUtf8(url),
            new_limit: parseInt(freeNet),
            new_public_limit: parseInt(freeNetLimit)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/updateasset', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    createProposal(parameters = false, issuerAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(issuerAddress)) {
            options = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createProposal, parameters, issuerAddress, options);

        if (this.validator.notValid([
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            }
        ], callback))
            return;

        const invalid = 'Error: code id: 20013';

        if (!parameters)
            return callback(invalid);

        if (!tools.isArray(parameters))
            parameters = [parameters];

        for (let parameter of parameters) {
            if (!tools.isObject(parameter))
                return callback(invalid);
        }

        const data = {
            owner_address: toHex(issuerAddress),
            parameters: parameters
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/proposalcreate', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    createGSCExchange(tokenName, tokenBalance, gscBalance, ownerAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createGSCExchange, tokenName, tokenBalance, gscBalance, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'token balance',
                type: 'positive-integer',
                value: tokenBalance
            },
            {
                name: 'gsc balance',
                type: 'positive-integer',
                value: gscBalance
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            first_token_id: fromUtf8(tokenName),
            first_token_balance: tokenBalance,
            second_token_id: '5f',
            second_token_balance: gscBalance
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/exchangecreate', data, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    createTokenExchange(firstTokenName, firstTokenBalance, secondTokenName, secondTokenBalance, ownerAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.createTokenExchange, firstTokenName, firstTokenBalance, secondTokenName, secondTokenBalance, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'first token name',
                type: 'not-empty-string',
                value: firstTokenName
            },
            {
                name: 'second token name',
                type: 'not-empty-string',
                value: secondTokenName
            },
            {
                name: 'first token balance',
                type: 'positive-integer',
                value: firstTokenBalance
            },
            {
                name: 'second token balance',
                type: 'positive-integer',
                value: secondTokenBalance
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            first_token_id: fromUtf8(firstTokenName),
            first_token_balance: firstTokenBalance,
            second_token_id: fromUtf8(secondTokenName),
            second_token_balance: secondTokenBalance
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/exchangecreate', data, 'post').then(resources => {
            callback(null, resources);
        }).catch(err => callback(err));
    }

    deleteProposal(proposalID = false, issuerAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(issuerAddress)) {
            callback = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(issuerAddress)) {
            options = issuerAddress;
            issuerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.deleteProposal, proposalID, issuerAddress, options);

        if (this.validator.notValid([
            {
                name: 'issuer',
                type: 'address',
                value: issuerAddress
            },
            {
                name: 'proposalID',
                type: 'integer',
                value: proposalID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(issuerAddress),
            proposal_id: parseInt(proposalID)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/proposaldelete', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    voteProposal(proposalID = false, isApproval = false, voterAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(voterAddress)) {
            callback = voterAddress;
            voterAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(voterAddress)) {
            options = voterAddress;
            voterAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.voteProposal, proposalID, isApproval, voterAddress, options);

        if (this.validator.notValid([
            {
                name: 'voter',
                type: 'address',
                value: voterAddress
            },
            {
                name: 'proposalID',
                type: 'integer',
                value: proposalID,
                gte: 0
            },
            {
                name: 'has approval',
                type: 'boolean',
                value: isApproval
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(voterAddress),
            proposal_id: parseInt(proposalID),
            is_add_approval: isApproval
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/proposalapprove', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    injectExchangeTokens(exchangeID = false, tokenName = false, tokenAmount = 0, ownerAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.injectExchangeTokens, exchangeID, tokenName, tokenAmount, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'token amount',
                type: 'integer',
                value: tokenAmount,
                gte: 1
            },
            {
                name: 'exchangeID',
                type: 'integer',
                value: exchangeID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: fromUtf8(tokenName),
            quant: parseInt(tokenAmount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/exchangeinject', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    withdrawExchangeTokens(exchangeID = false, tokenName = false, tokenAmount = 0, ownerAddress = this.gscWeb3.defaultAddress.hex, options, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.withdrawExchangeTokens, exchangeID, tokenName, tokenAmount, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'token amount',
                type: 'integer',
                value: tokenAmount,
                gte: 1
            },
            {
                name: 'exchangeID',
                type: 'integer',
                value: exchangeID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: fromUtf8(tokenName),
            quant: parseInt(tokenAmount)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/exchangewithdraw', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    tradeExchangeTokens(exchangeID = false,
                        tokenName = false,
                        tokenAmountSold = 0,
                        tokenAmountExpected = 0,
                        ownerAddress = this.gscWeb3.defaultAddress.hex,
                        options,
                        callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.tradeExchangeTokens, exchangeID, tokenName, tokenAmountSold, tokenAmountExpected, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'token name',
                type: 'not-empty-string',
                value: tokenName
            },
            {
                name: 'tokenAmountSold',
                type: 'integer',
                value: tokenAmountSold,
                gte: 1
            },
            {
                name: 'tokenAmountExpected',
                type: 'integer',
                value: tokenAmountExpected,
                gte: 1
            },
            {
                name: 'exchangeID',
                type: 'integer',
                value: exchangeID,
                gte: 0
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            exchange_id: parseInt(exchangeID),
            token_id: this.gscWeb3.fromAscii(tokenName),
            quant: parseInt(tokenAmountSold),
            expected: parseInt(tokenAmountExpected)
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/exchangetransaction', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateSetting(contractAddress = false,
                  userFeePercentage = false,
                  ownerAddress = this.gscWeb3.defaultAddress.hex,
                  options,
                  callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateSetting, contractAddress, userFeePercentage, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'contract',
                type: 'address',
                value: contractAddress
            },
            {
                name: 'userFeePercentage',
                type: 'integer',
                value: userFeePercentage,
                gte: 0,
                lte: 100
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            contract_address: toHex(contractAddress),
            consume_user_resource_percent: userFeePercentage
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/updatesetting', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateCpuLimit(contractAddress = false,
                      originCpuLimit = false,
                      ownerAddress = this.gscWeb3.defaultAddress.hex,
                      options,
                      callback = false) {

        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (tools.isFunction(ownerAddress)) {
            callback = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        } else if (tools.isObject(ownerAddress)) {
            options = ownerAddress;
            ownerAddress = this.gscWeb3.defaultAddress.hex;
        }

        if (!callback)
            return this.injectPromise(this.updateCpuLimit, contractAddress, originCpuLimit, ownerAddress, options);

        if (this.validator.notValid([
            {
                name: 'owner',
                type: 'address',
                value: ownerAddress
            },
            {
                name: 'contract',
                type: 'address',
                value: contractAddress
            },
            {
                name: 'originCpuLimit',
                type: 'integer',
                value: originCpuLimit,
                gte: 0,
                lte: 10_000_000
            }
        ], callback))
            return;

        const data = {
            owner_address: toHex(ownerAddress),
            contract_address: toHex(contractAddress),
            origin_cpu_limit: originCpuLimit
        };

        if (options && options.permissionId) {
            data.Permission_id = options.permissionId;
        }

        this.gscWeb3.fullNode.request('wallet/updatecpulimit', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

    updateAccountPermissions(ownerAddress = this.gscWeb3.defaultAddress.hex,
                             ownerPermissions = false,
                             witnessPermissions = false,
                             activesPermissions = false,
                             callback = false) {

        if (tools.isFunction(activesPermissions)) {
            callback = activesPermissions;
            activesPermissions = false;
        }

        if (tools.isFunction(witnessPermissions)) {
            callback = witnessPermissions;
            witnessPermissions = activesPermissions = false;
        }

        if (tools.isFunction(ownerPermissions)) {
            callback = ownerPermissions;
            ownerPermissions = witnessPermissions = activesPermissions = false;
        }

        if (!callback)
            return this.injectPromise(this.updateAccountPermissions, ownerAddress, ownerPermissions, witnessPermissions, activesPermissions);

        if (!this.gscWeb3.isAddress(ownerAddress))
            return callback('Error: code id: 20014');

        if (!this.checkPermissions(ownerPermissions, 0)) {
            return callback('Error: code id: 20015');
        }

        if (!this.checkPermissions(witnessPermissions, 1)) {
            return callback('Error: code id: 20016');
        }

        if (!Array.isArray(activesPermissions)) {
            activesPermissions = [activesPermissions]
        }

        for (let activesPermission of activesPermissions) {
            if (!this.checkPermissions(activesPermission, 2)) {
                return callback('Error: code id: 20017');
            }
        }

        const data = {
            owner_address: ownerAddress
        }
        if (ownerPermissions) {
            data.owner = ownerPermissions
        }
        if (witnessPermissions) {
            data.witness = witnessPermissions
        }
        if (activesPermissions) {
            data.actives = activesPermissions.length === 1 ? activesPermissions[0] : activesPermissions
        }

        this.gscWeb3.fullNode.request('wallet/accountpermissionupdate', data, 'post').then(transaction => resultManager(transaction, callback)).catch(err => callback(err));
    }

}
