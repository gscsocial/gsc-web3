import axios from 'axios';
import tools from 'tools';

export default class getRequest {
    constructor(host, timeout = 30000, user = false, password = false, headers = {}, statusPage = '/') {
        if (!tools.isValidURL(host))
            throw new Error('Error: code id: 50001');

        if (isNaN(timeout) || timeout < 0)
            throw new Error('Error: code id: 50002');

        if (!tools.isObject(headers))
            throw new Error('Error: code id: 50003');

        host = host.replace(/\/+$/, '');

        this.host = host;
        this.timeout = timeout;
        this.user = user;
        this.password = password;
        this.headers = headers;
        this.statusPage = statusPage;

        this.instance = axios.create({
            baseURL: host,
            timeout: timeout,
            headers: headers,
            auth: user && {
                user,
                password
            },
        });
    }

    async isConnected(statusPage = this.statusPage) {
        return this.request(statusPage).then(data => {
            return tools.hasProperties(data, 'blockID', 'block_header');
        }).catch(() => false);
    }

    setStatusPage(statusPage = '/') {
        this.statusPage = statusPage;
    }

    request(url, payload = {}, method = 'get') {
        method = method.toLowerCase();

        return this.instance.request({
            data: method == 'post' && Object.keys(payload).length ? payload : null,
            params: method == 'get' && payload,
            url,
            method
        }).then(({data}) => data);
    }
};
