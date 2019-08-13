import GSCWeb3 from 'index';
import tools from 'tools';
import Method from './gsc';

export default class Contract {
    constructor(gscWeb3 = false, abi = [], address = false) {
        if (!gscWeb3 || !gscWeb3 instanceof GSCWeb3)
            throw new Error('Expected instance of GSCWeb3');

        this.gscWeb3 = gscWeb3;
        this.injectPromise = tools.promiseInjector(this);

        this.address = address;
        this.abi = abi;

        this.eventListener = false;
        this.bytecode = false;
        this.deployed = false;
        this.lastBlock = false;

        this.methods = {};
        this.methodInstances = {};
        this.props = [];

        if (this.gscWeb3.isAddress(address))
            this.deployed = true;
        else this.address = false;

        this.loadAbi(abi);
    }

    async _getEvents(options = {}) {
        const events = await this.gscWeb3.event.getEventsByContractAddress(this.address, options);
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

            if (!this.lastBlock)
                return true;

            return event.block > this.lastBlock;
        });

        if (latestEvent)
            this.lastBlock = latestEvent.block;

        return newEvents;
    }

    async _startEventListener(options = {}, callback) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (this.eventListener)
            clearInterval(this.eventListener);

        if (!this.gscWeb3.eventServer)
            throw new Error('Error: code id: 30010');

        if (!this.address)
            throw new Error('Error: code id: 30011');

        this.eventCallback = callback;
        await this._getEvents(options);

        this.eventListener = setInterval(() => {
            this._getEvents(options).then(newEvents => newEvents.forEach(event => {
                this.eventCallback && this.eventCallback(event)
            })).catch(err => {
                console.error('Failed to get event list', err);
            });
        }, 3000);
    }

    _stopEventListener() {
        if (!this.eventListener)
            return;

        clearInterval(this.eventListener);
        this.eventListener = false;
        this.eventCallback = false;
    }

    async at(contractAddress, callback = false) {
        if (!callback)
            return this.injectPromise(this.at, contractAddress);

        try {
            const contract = await this.gscWeb3.gsc.getContract(contractAddress);

            if (!contract.contract_address)
                return callback('Unknown error: ' + JSON.stringify(contract, null, 2));

            this.address = contract.contract_address;
            this.bytecode = contract.bytecode;
            this.deployed = true;

            this.loadAbi(contract.abi.entrys);

            return callback(null, this);
        } catch (ex) {
            if (ex.toString().includes('Error: code id: 30012'))
                return callback('Error: code id: 30013');

            return callback(ex);
        }
    }

    decodeInput(data) {

        const methodName = data.substring(0, 8);
        const inputData = data.substring(8);

        if (!this.methodInstances[methodName])
            throw new Error('Error: Contract method ' + methodName + " not found");

        const methodInstance = this.methodInstances[methodName];

        return {
            name: methodInstance.name,
            params: this.methodInstances[methodName].decodeInput(inputData),
        }
    }

    events(options = {}, callback = false) {
        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!tools.isFunction(callback))
            throw new Error('Error: code id: 30014');

        const self = this;

        return {
            start(startCallback = false) {
                if (!startCallback) {
                    self._startEventListener(options, callback);
                    return this;
                }

                self._startEventListener(options, callback).then(() => {
                    startCallback();
                }).catch(err => {
                    startCallback(err)
                });

                return this;
            },
            stop() {
                self._stopEventListener();
            }
        };
    }

    hasProperty(property) {
        return this.hasOwnProperty(property) || this.__proto__.hasOwnProperty(property);
    }

    loadAbi(abi) {
        this.abi = abi;
        this.methods = {};

        this.props.forEach(prop => delete this[prop]);

        abi.forEach(func => {
            // Don't build a method for constructor function. That's handled through contract create.
            if (!func.type || /constructor/i.test(func.type))
                return;

            const method = new Method(this, func);
            const methodCall = method.onMethod.bind(method);

            const {
                name,
                functionSelector,
                signature
            } = method;

            this.methods[name] = methodCall;
            this.methods[functionSelector] = methodCall;
            this.methods[signature] = methodCall;

            this.methodInstances[name] = method;
            this.methodInstances[functionSelector] = method;
            this.methodInstances[signature] = method;

            if (!this.hasProperty(name)) {
                this[name] = methodCall;
                this.props.push(name);
            }

            if (!this.hasProperty(functionSelector)) {
                this[functionSelector] = methodCall;
                this.props.push(functionSelector);
            }

            if (!this.hasProperty(signature)) {
                this[signature] = methodCall;
                this.props.push(signature);
            }
        });
    }

    async new(options, privateKey = this.gscWeb3.defaultPrivateKey, callback = false) {
        if (tools.isFunction(privateKey)) {
            callback = privateKey;
            privateKey = this.gscWeb3.defaultPrivateKey;
        }

        if (!callback)
            return this.injectPromise(this.new, options, privateKey);

        try {
            const address = this.gscWeb3.address.fromPrivateKey(privateKey);
            const transaction = await this.gscWeb3.transactionBuilder.createSmartContract(options, address);
            const signedTransaction = await this.gscWeb3.gsc.sign(transaction, privateKey);
            const contract = await this.gscWeb3.gsc.sendRawTransaction(signedTransaction);

            if (contract.code)
                return callback({
                    error: contract.code,
                    message: this.gscWeb3.toUtf8(contract.message)
                })

            await tools.sleep(3000);
            return this.at(signedTransaction.contract_address, callback);
        } catch (ex) {
            return callback(ex);
        }
    }

}
