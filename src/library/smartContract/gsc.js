import tools from 'tools';
import {ADDRESS_PREFIX_REGEX} from 'tools/address';

const decodeOutput = (abi, output) => {
    const names = abi.map(({name}) => name).filter(name => !!name);
    const types = abi.map(({type}) => type);

    return tools.abi.decodeParams(names, types, output);
};

const getFunctionSelector = abi => {
    return abi.name + '(' + getParamTypes(abi.inputs || []).join(',') + ')';
}

const getParamTypes = params => {
    return params.map(({type}) => type);
}

export default class Method {
    constructor(contract, abi) {
        this.gscWeb3 = contract.gscWeb3;
        this.contract = contract;

        this.abi = abi;
        this.name = abi.name || (abi.name = abi.type);

        this.inputs = abi.inputs || [];
        this.outputs = abi.outputs || [];

        this.functionSelector = getFunctionSelector(abi);
        this.signature = this.gscWeb3.sha3(this.functionSelector, false).slice(0, 8);
        this.injectPromise = tools.promiseInjector(this);

        this.defaultOptions = {
            feeLimit: 1000000000,
            callValue: 0,
            userFeePercentage: 100,
            shouldPollResponse: false
        };
    }

    async _call(types, args, options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this._call, types, args, options);

        if (types.length !== args.length)
            return callback('Error: code id: 40001');

        if (!this.contract.address)
            return callback('Error: code id: 40002');

        if (!this.contract.deployed)
            return callback('Error: code id: 40003');

        const {stateMutability} = this.abi;

        if (!['pure', 'view'].includes(stateMutability.toLowerCase()))
            return callback('Error: code id: 40004');

        options = {
            ...this.defaultOptions,
            from: this.gscWeb3.defaultAddress.hex,
            ...options,
        };

        const parameters = args.map((value, index) => ({
            type: types[index],
            value
        }));

        this.gscWeb3.transactionBuilder.triggerSmartContract(
            this.contract.address,
            this.functionSelector,
            options,
            parameters,
            options.from ? this.gscWeb3.address.toHex(options.from) : false,
            (err, transaction) => {
                if (err)
                    return callback(err);

                if (!tools.hasProperty(transaction, 'constant_result'))
                    return callback('Error: code id: 40005');

                try {

                    const len = transaction.constant_result[0].length
                    if (len === 0 || len % 64 === 8) {
                        let msg = 'The call has been reverted or has thrown an error.'
                        if (len !== 0) {
                            msg += ' Error message: '
                            let msg2 = ''
                            let chunk = transaction.constant_result[0].substring(8)
                            for (let i = 0; i < len - 8; i += 64) {
                                msg2 += this.gscWeb3.toUtf8(chunk.substring(i, i + 64))
                            }
                            msg += msg2.replace(/(\u0000|\u000b|\f)+/g, ' ').replace(/ +/g, ' ').replace(/\s+$/g, '');
                        }
                        return callback(msg)
                    }

                    let output = decodeOutput(this.outputs, '0x' + transaction.constant_result[0]);

                    if (output.length === 1)
                        output = output[0];

                    return callback(null, output);
                } catch (ex) {
                    return callback(ex);
                }
            });
    }

    async _send(types, args, options = {}, privateKey = this.gscWeb3.defaultPrivateKey, callback = false) {
        if (tools.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.gscWeb3.defaultPrivateKey;
        }

        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this._send, types, args, options, privateKey);

        if (types.length !== args.length)
            throw new Error('Error: code id: 40001');

        if (!this.contract.address)
            return callback('Error: code id: 40002');

        if (!this.contract.deployed)
            return callback('Error: code id: 40003');

        const {stateMutability} = this.abi;

        if (['pure', 'view'].includes(stateMutability.toLowerCase()))
            return callback('Error: code id: 40004');

        // If a function isn't payable, dont provide a callValue.
        if (!['payable'].includes(stateMutability.toLowerCase()))
            options.callValue = 0;

        options = {
            ...this.defaultOptions,
            from: this.gscWeb3.defaultAddress.hex,
            ...options,
        };

        const parameters = args.map((value, index) => ({
            type: types[index],
            value
        }));

        try {
            const address = privateKey ? this.gscWeb3.address.fromPrivateKey(privateKey) : this.gscWeb3.defaultAddress.base58;
            const transaction = await this.gscWeb3.transactionBuilder.triggerSmartContract(
                this.contract.address,
                this.functionSelector,
                options,
                parameters,
                this.gscWeb3.address.toHex(address)
            );

            if (!transaction.result || !transaction.result.result)
                return callback('Error: Unknown error: ' + JSON.stringify(transaction, null, 2));

            // If privateKey is false, this won't be signed here. We assume sign functionality will be replaced.
            const signedTransaction = await this.gscWeb3.gsc.sign(transaction.transaction, privateKey);

            if (!signedTransaction.signature) {
                if (!privateKey)
                    return callback('Error: code id: 40006');

                return callback('Error: code id: 40007');
            }

            const broadcast = await this.gscWeb3.gsc.sendRawTransaction(signedTransaction);

            if (broadcast.code) {
                const err = {
                    error: broadcast.code,
                    message: broadcast.code
                };
                if (broadcast.message)
                    err.message = this.gscWeb3.toUtf8(broadcast.message);
                return callback(err)
            }

            if (!options.shouldPollResponse)
                return callback(null, signedTransaction.txID);

            const checkResult = async (index = 0) => {
                if (index == 20) {
                    return callback({
                        error: 'Error: code id: 40008',
                        transaction: signedTransaction
                    });
                }

                const output = await this.gscWeb3.gsc.getTransactionInfo(signedTransaction.txID);

                if (!Object.keys(output).length) {
                    return setTimeout(() => {
                        checkResult(index + 1);
                    }, 3000);
                }

                if (output.result && output.result == 'FAILED') {
                    return callback({
                        error: this.gscWeb3.toUtf8(output.resMessage),
                        transaction: signedTransaction,
                        output
                    });
                }

                if (!tools.hasProperty(output, 'contractResult')) {
                    return callback({
                        error: 'Error: Failed to execute: ' + JSON.stringify(output, null, 2),
                        transaction: signedTransaction,
                        output
                    });
                }

                if (options.rawResponse)
                    return callback(null, output);

                let decoded = decodeOutput(this.outputs, '0x' + output.contractResult[0]);

                if (decoded.length === 1)
                    decoded = decoded[0];

                return callback(null, decoded);
            }

            checkResult();
        } catch (ex) {
            return callback(ex);
        }
    }

    async _watch(options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!tools.isFunction(callback))
            throw new Error('Error: code id: 40009');

        if (!this.contract.address)
            return callback('Error: code id: 40002');

        if (!this.abi.type || !/event/i.test(this.abi.type))
            return callback('Error: code id: 40010');

        if (!this.gscWeb3.eventServer)
            return callback('Error: code id: 30001');

        let listener = false;
        let lastBlock = false;
        let since = Date.now() - 1000;

        const getEvents = async () => {
            try {

                const params = {
                    since,
                    eventName: this.name,
                    sort: 'block_timestamp',
                    blockNumber: 'latest',
                    filters: options.filters
                }
                if (options.resourceNode) {
                    if (/full/i.test(options.resourceNode))
                        params.onlyUnconfirmed = true
                    else
                        params.onlyConfirmed = true
                }

                const events = await this.gscWeb3.event.getEventsByContractAddress(this.contract.address, params);
                const [latestEvent] = events.sort((a, b) => b.block - a.block);
                const newEvents = events.filter((event, index) => {

                    if (options.resourceNode && event.resourceNode &&
                        options.resourceNode.toLowerCase() !== event.resourceNode.toLowerCase()) {
                        return false
                    }

                    const duplicate = events.slice(0, index).some(priorEvent => (
                        JSON.stringify(priorEvent) == JSON.stringify(event)
                    ));

                    if (duplicate)
                        return false;

                    if (!lastBlock)
                        return true;

                    return event.block > lastBlock;
                });

                if (latestEvent)
                    lastBlock = latestEvent.block;

                return newEvents;
            } catch (ex) {
                return Promise.reject(ex);
            }

        };

        const bindListener = () => {
            if (listener)
                clearInterval(listener);

            listener = setInterval(() => {
                getEvents().then(events => events.forEach(event => {
                    callback(null, tools.parseEvent(event, this.abi))
                })).catch(err => callback(err));
            }, 3000);
        };

        await getEvents();
        bindListener();

        return {
            start: bindListener(),
            stop: () => {
                if (!listener)
                    return;

                clearInterval(listener);
                listener = false;
            }
        }
    }

    decodeInput(data) {
        return decodeOutput(this.inputs, '0x' + data);
    }

    onMethod(...args) {
        const types = getParamTypes(this.inputs);

        args.forEach((arg, index) => {
            if (types[index] == 'address')
                args[index] = this.gscWeb3.address.toHex(arg).replace(ADDRESS_PREFIX_REGEX, '0x')

            if (types[index] == 'address[]') {
                args[index] = args[index].map(address => {
                    return this.gscWeb3.address.toHex(address).replace(ADDRESS_PREFIX_REGEX, '0x')
                })
            }
        });

        return {
            call: (...methodArgs) => this._call(types, args, ...methodArgs),
            send: (...methodArgs) => this._send(types, args, ...methodArgs),
            watch: (...methodArgs) => this._watch(...methodArgs)
        }
    }

}
