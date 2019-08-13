import GSCWeb3 from 'index';
import tools from 'tools';

export default class Validator {

    constructor(gscWeb3 = false) {
        if (!gscWeb3 || !gscWeb3 instanceof GSCWeb3)
            throw new Error('Expected instance of GSCWeb3');
        this.gscWeb3 = gscWeb3;
    }

    invalid(param) {
        return param.msg || `Invalid ${param.name}${param.type === 'address' ? ' address' : ''} provided`;
    }

    notPositive(param) {
        return `${param.name} must be a positive integer`;
    }

    notEqual(param) {
        return param.msg || `${param.names[0]} can not be equal to ${param.names[1]}`;
    }

    notValid(params = [], callback = new Function) {

        let normalized = {};
        let no = false;
        for (const param of params) {
            let {
                name,
                names,
                value,
                type,
                gt,
                lt,
                gte,
                lte,
                se,
                optional
            } = param;
            if (optional && (
                !tools.isNotNullOrUndefined(value)
                || (type !== 'boolean' && value === false)))
                continue;
            normalized[param.name] = param.value;
            switch (type) {

                case 'address':
                    if (!this.gscWeb3.isAddress(value)) {
                        no = true;
                    } else {
                        normalized[name] = this.gscWeb3.address.toHex(value);
                    }
                    break;

                case 'integer':
                    if (!tools.isInteger(value) ||
                        (typeof gt === 'number' && value <= param.gt) ||
                        (typeof lt === 'number' && value >= param.lt) ||
                        (typeof gte === 'number' && value < param.gte) ||
                        (typeof lte === 'number' && value > param.lte)) {
                        no = true;
                    }
                    break;

                case 'positive-integer':
                    if (!tools.isInteger(value) || value <= 0) {
                        callback(this.notPositive(param));
                        return;
                    }
                    break;

                case 'tokenId':
                    if (!tools.isString(value) || !value.length) {
                        no = true;
                    }
                    break;

                case 'notEmptyObject':
                    if (!tools.isObject(value) || !Object.keys(value).length) {
                        no = true;
                    }
                    break;

                case 'notEqual':
                    if (normalized[names[0]] === normalized[names[1]]) {
                        callback(this.notEqual(param));
                        return true;
                    }
                    break;

                case 'resource':
                    if (!['NET', 'CPU'].includes(value)) {
                        no = true;
                    }
                    break;

                case 'url':
                    if (!tools.isValidURL(value)) {
                        no = true;
                    }
                    break;

                case 'hex':
                    if (!tools.isHex(value)) {
                        no = true;
                    }
                    break;

                case 'array':
                    if (!Array.isArray(value)) {
                        no = true;
                    }
                    break;

                case 'not-empty-string':
                    if (!tools.isString(value) || !value.length) {
                        no = true;
                    }
                    break;

                case 'boolean':
                    if (!tools.isBoolean(value)) {
                        no = true;
                    }
                    break;
                case 'string':
                    if (!tools.isString(value) ||
                        (typeof gt === 'number' && value.length <= param.gt) ||
                        (typeof lt === 'number' && value.length >= param.lt) ||
                        (typeof gte === 'number' && value.length < param.gte) ||
                        (typeof lte === 'number' && value.length > param.lte)) {
                        no = true;
                    }
                    break;
            }
            if (no) {
                callback(this.invalid(param));
                return true;
            }
        }
        return false;
    }
}

