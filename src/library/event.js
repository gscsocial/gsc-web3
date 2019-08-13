import GSCWeb3 from 'index';
import tools from 'tools';
import providers from "./request";
import querystring from "querystring";

export default class Event {

    constructor(gscWeb3 = false) {
        if (!gscWeb3 || !(gscWeb3 instanceof GSCWeb3))
            throw new Error('Expected instance of GSCWeb3');
        this.gscWeb3 = gscWeb3;
        this.injectPromise = tools.promiseInjector(this);
    }

    setServer(eventServer = false, healthcheck = 'healthcheck') {
        if (!eventServer)
            return this.gscWeb3.eventServer = false;

        if (tools.isString(eventServer))
            eventServer = new providers.getRequest(eventServer);

        if (!this.gscWeb3.isValidProvider(eventServer))
            throw new Error('Invalid event server provided');

        this.gscWeb3.eventServer = eventServer;
        this.gscWeb3.eventServer.isConnected = () => this.gscWeb3.eventServer.request(healthcheck).then(() => true).catch(() => false);
    }

    getEventsByContractAddress(contractAddress = false, options = {}, callback = false) {

        let {
            sinceTimestamp,
            since,
            fromTimestamp,
            eventName,
            blockNumber,
            size,
            page,
            onlyConfirmed,
            onlyUnconfirmed,
            previousLastEventFingerprint,
            previousFingerprint,
            fingerprint,
            rawResponse,
            sort,
            filters
        } = Object.assign({
            sinceTimestamp: 0,
            eventName: false,
            blockNumber: false,
            size: 20,
            page: 1
        }, options)

        if (!callback)
            return this.injectPromise(this.getEventsByContractAddress, contractAddress, options);

        fromTimestamp = fromTimestamp || sinceTimestamp || since;

        if (!this.gscWeb3.eventServer)
            return callback('Error: code id: 30001');

        const routeParams = [];

        if (!this.gscWeb3.isAddress(contractAddress))
            return callback('Error: code id: 20009');

        if (eventName && !contractAddress)
            return callback('Error: code id: 30002');

        if (typeof fromTimestamp !== 'undefined' && !tools.isInteger(fromTimestamp))
            return callback('Error: code id: 30003');

        if (!tools.isInteger(size))
            return callback('Error: code id: 30004');

        if (size > 200) {
            console.warn('Error: code id: 30005');
            size = 200;
        }

        if (!tools.isInteger(page))
            return callback('Error: code id: 30006');

        if (blockNumber && !eventName)
            return callback('Error: code id: 30007');

        if (contractAddress)
            routeParams.push(this.gscWeb3.address.fromHex(contractAddress));

        if (eventName)
            routeParams.push(eventName);

        if (blockNumber)
            routeParams.push(blockNumber);

        const qs = {
            size,
            page
        }
        
        if (typeof filters === 'object' && Object.keys(filters).length > 0) {
            qs.filters = JSON.stringify(filters);
        }

        if (fromTimestamp) {
            qs.fromTimestamp = qs.since = fromTimestamp;
        }

        if (onlyConfirmed)
            qs.onlyConfirmed = onlyConfirmed

        if (onlyUnconfirmed && !onlyConfirmed)
            qs.onlyUnconfirmed = onlyUnconfirmed

        if (sort)
            qs.sort = sort

        fingerprint = fingerprint || previousFingerprint || previousLastEventFingerprint
        if (fingerprint)
            qs.fingerprint = fingerprint

        return this.gscWeb3.eventServer.request(`event/contract/${routeParams.join('/')}?${querystring.stringify(qs)}`).then((data = false) => {
            if (!data)
                return callback('Error: code id: 30008');

            if (!tools.isArray(data))
                return callback(data);

            return callback(null,
                rawResponse === true ? data : data.map(event => tools.mapEvent(event))
            );
        }).catch(err => callback((err.response && err.response.data) || err));
    }

    getEventsByTransactionID(transactionID = false, options = {}, callback = false) {

        if (tools.isFunction(options)) {
            callback = options;
            options = {};
        }

        if (!callback)
            return this.injectPromise(this.getEventsByTransactionID, transactionID, options);

        if (!this.gscWeb3.eventServer)
            return callback('Error: code id: 30009');

        return this.gscWeb3.eventServer.request(`event/transaction/${transactionID}`).then((data = false) => {
            if (!data)
                return callback('Error: code id: 30008');

            if (!tools.isArray(data))
                return callback(data);

            return callback(null,
                options.rawResponse === true ? data : data.map(event => tools.mapEvent(event))
            );
        }).catch(err => callback((err.response && err.response.data) || err));
    }

}

